// SMP reference relay server.
//
// Wire format (big-endian):
//
//   Client -> Server handshake:
//     4 bytes "SMP0", 1 byte version=2, 1 byte mode (0=PULL,1=PUSH),
//     2 bytes path length, N bytes path,
//     16 bytes session id (all-zero = anonymous publisher; non-zero lets a
//     publisher reconnect to the same path without dropping subscribers).
//
//   Server -> Client response:
//     4 bytes "SMP0", 1 byte version, 1 byte status
//       (0=OK, 1=bad handshake, 2=path occupied by another publisher)
//
//   After handshake, the connection is a stream of length-prefixed messages
//   that carry serialized AVPackets / stream headers from the smp muxer.
//   Each message is:
//
//     4 bytes length L (excludes this length field)
//     1 byte  type
//     L-1 bytes payload
//
//   Types:
//     0x01 HEADER  (stream descriptions, sent once per session)
//     0x02 PACKET  (regular packet)
//     0x03 KEY     (primary stream keyframe — GOP boundary)
//
// Server semantics:
//
//   - Per stream path it keeps the most recent HEADER and the current GOP
//     (every PACKET/KEY since the last KEY, KEY at index 0).
//   - On a new KEY the GOP is reset, so a fresh subscriber catches up with
//     HEADER + current GOP + live packets — join latency = one keyframe
//     interval (and zero for primary=audio streams since AAC frames are
//     all keys).
//   - When a publisher disconnects the stream is kept alive: subscribers
//     remain attached and the cached header/GOP are preserved.
//   - A new publisher connecting to the same path takes over only if the
//     previous publisher is gone. If the new session id is non-zero and
//     matches the previous session id the existing GOP is kept (true
//     seamless reconnect); otherwise the GOP is dropped because the codec
//     parameters may have changed.
//   - GOP byte size is tracked and a warning is emitted if it grows past
//     gopWarnBytes (long IDR interval / runaway).
//
// Usage:
//   smp -addr :7777 [-log debug|info|warn|error]
//
//   ffmpeg -re -i input.mp4 -c copy -f smp smp://host:7777/live
//   ffplay -f smp smp://host:7777/live

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// --- protocol constants ---

const (
	magic    = "SMP0"
	version  = 2
	modePull = 0
	modePush = 1

	statusOK       = 0
	statusBadHello = 1
	statusOccupied = 2

	msgHeader = 0x01
	msgPacket = 0x02
	msgKey    = 0x03

	sessionIDLen   = 16
	subBuffer      = 1024
	maxMessageLen  = 64 * 1024 * 1024
	gopWarnBytes   = 32 * 1024 * 1024
	headerWaitTime = 10 * time.Second
)

// --- logger (mirrors livsho/backend conventions) ---

type logLevel int

const (
	DebugLevel logLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

const (
	ansiReset  = "\033[0m"
	ansiWhite  = "\033[97m"
	ansiGreen  = "\033[1;92m"
	ansiYellow = "\033[1;93m"
	ansiRed    = "\033[1;91m"
	ansiBlue   = "\033[1;94m"
)

type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level logLevel
}

var logger = &Logger{out: os.Stderr, level: InfoLevel}

func (l *Logger) SetLevel(lvl logLevel) {
	l.mu.Lock()
	l.level = lvl
	l.mu.Unlock()
}

func (l *Logger) write(lvl logLevel, color, label, msg string, args ...any) {
	if lvl < l.level {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	var line strings.Builder
	fmt.Fprintf(&line, "%s%s%s %s%s%s %s", ansiWhite, ts, ansiReset, color, label, ansiReset, msg)
	for i := 0; i+1 < len(args); i += 2 {
		fmt.Fprintf(&line, " %s%v%s=%v", ansiWhite, args[i], ansiReset, args[i+1])
	}
	l.mu.Lock()
	fmt.Fprintln(l.out, line.String())
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, args ...any) { l.write(DebugLevel, ansiBlue, "DEBU", msg, args...) }
func (l *Logger) Info(msg string, args ...any)  { l.write(InfoLevel, ansiGreen, "INFO", msg, args...) }
func (l *Logger) Warn(msg string, args ...any)  { l.write(WarnLevel, ansiYellow, "WARN", msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.write(ErrorLevel, ansiRed, "ERRO", msg, args...) }
func (l *Logger) Fatal(msg any, args ...any) {
	l.write(ErrorLevel, ansiRed, "FATA", fmt.Sprint(msg), args...)
	os.Exit(1)
}

func parseLevel(s string) (logLevel, error) {
	switch strings.ToLower(s) {
	case "debug":
		return DebugLevel, nil
	case "info":
		return InfoLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "error":
		return ErrorLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level %q", s)
	}
}

// --- messages ---

// message holds a single length-prefixed payload as it travels on the wire,
// already concatenated with its 4-byte length prefix so we can write it back
// out with one syscall.
type message struct {
	framed []byte // 4-byte length + payload
	mtype  byte
	size   int
}

func newMessage(payload []byte) *message {
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(payload)))
	copy(framed[4:], payload)
	return &message{framed: framed, mtype: payload[0], size: len(framed)}
}

// --- streams + hub ---

type stream struct {
	path string

	mu              sync.Mutex
	cond            *sync.Cond
	subs            map[chan *message]struct{}
	header          *message
	gop             []*message
	gopBytes        int
	gopWarned       bool
	publisherActive bool
	sessionID       [sessionIDLen]byte
	hasSession      bool

	droppedFrames uint64
}

func newStream(path string) *stream {
	s := &stream{path: path, subs: make(map[chan *message]struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// claim attempts to make the caller the active publisher. Returns ok=false if
// another publisher is currently active. seamless==true means the existing
// header + GOP were preserved (true reconnect).
func (s *stream) claim(sid [sessionIDLen]byte, hasSession bool) (ok, seamless bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publisherActive {
		return false, false
	}

	seamless = hasSession && s.hasSession && s.sessionID == sid && s.header != nil
	if !seamless {
		s.header = nil
		s.gop = nil
		s.gopBytes = 0
		s.gopWarned = false
	}
	s.sessionID = sid
	s.hasSession = hasSession
	s.publisherActive = true
	return true, seamless
}

func (s *stream) release() {
	s.mu.Lock()
	s.publisherActive = false
	s.mu.Unlock()
}

func (s *stream) setHeader(m *message) {
	s.mu.Lock()
	s.header = m
	s.gop = nil
	s.gopBytes = 0
	s.gopWarned = false
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *stream) publish(m *message) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case m.mtype == msgKey:
		s.gop = []*message{m}
		s.gopBytes = m.size
		s.gopWarned = false
	case len(s.gop) > 0:
		s.gop = append(s.gop, m)
		s.gopBytes += m.size
		if !s.gopWarned && s.gopBytes > gopWarnBytes {
			logger.Warn("gop exceeded byte threshold without keyframe",
				"path", s.path, "bytes", s.gopBytes, "msgs", len(s.gop))
			s.gopWarned = true
		}
	}
	// PACKETs that arrive before the first KEY are forwarded live but not
	// kept in the GOP — a late subscriber starting from them would have no
	// reference frames.

	for ch := range s.subs {
		select {
		case ch <- m:
		default:
			s.droppedFrames++
		}
	}
}

func (s *stream) subscribe() (chan *message, *message, []*message, bool) {
	ch := make(chan *message, subBuffer)
	s.mu.Lock()
	defer s.mu.Unlock()

	deadline := time.Now().Add(headerWaitTime)
	for s.header == nil {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, nil, nil, false
		}
		timer := time.AfterFunc(remaining, func() {
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		})
		s.cond.Wait()
		timer.Stop()
	}

	s.subs[ch] = struct{}{}
	gop := make([]*message, len(s.gop))
	copy(gop, s.gop)
	return ch, s.header, gop, true
}

func (s *stream) unsubscribe(ch chan *message) {
	s.mu.Lock()
	if _, ok := s.subs[ch]; ok {
		delete(s.subs, ch)
		close(ch)
	}
	s.mu.Unlock()
}

func (s *stream) snapshot() (subs int, gopBytes int, gopMsgs int, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subs), s.gopBytes, len(s.gop), s.droppedFrames
}

type hub struct {
	mu      sync.Mutex
	streams map[string]*stream
}

func newHub() *hub {
	return &hub{streams: make(map[string]*stream)}
}

func (h *hub) get(path string) *stream {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.streams[path]
	if !ok {
		s = newStream(path)
		h.streams[path] = s
	}
	return s
}

// --- wire I/O ---

func readMessage(r io.Reader) (*message, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(l[:])
	if size == 0 || size > maxMessageLen {
		return nil, fmt.Errorf("bad message length %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return newMessage(payload), nil
}

type handshake struct {
	mode      byte
	path      string
	sessionID [sessionIDLen]byte
}

func (h *handshake) hasSession() bool {
	for _, b := range h.sessionID {
		if b != 0 {
			return true
		}
	}
	return false
}

func (h *handshake) sessionString() string {
	if !h.hasSession() {
		return "anonymous"
	}
	return hex.EncodeToString(h.sessionID[:])
}

func readHandshake(r io.Reader) (*handshake, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != magic {
		return nil, errors.New("bad magic")
	}
	if hdr[4] != version {
		return nil, fmt.Errorf("unsupported version %d", hdr[4])
	}
	mode := hdr[5]
	if mode != modePull && mode != modePush {
		return nil, fmt.Errorf("bad mode %d", mode)
	}
	pathLen := binary.BigEndian.Uint16(hdr[6:8])
	path := make([]byte, pathLen)
	if _, err := io.ReadFull(r, path); err != nil {
		return nil, err
	}
	hs := &handshake{mode: mode, path: string(path)}
	if _, err := io.ReadFull(r, hs.sessionID[:]); err != nil {
		return nil, err
	}
	return hs, nil
}

func writeResponse(w io.Writer, status byte) error {
	resp := []byte{'S', 'M', 'P', '0', version, status}
	_, err := w.Write(resp)
	return err
}

// --- server ---

type server struct {
	hub *hub
}

func (srv *server) handle(conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()

	hs, err := readHandshake(conn)
	if err != nil {
		logger.Warn("handshake rejected", "peer", peer, "err", err)
		_ = writeResponse(conn, statusBadHello)
		return
	}

	logger.Info("client connected",
		"peer", peer,
		"mode", modeName(hs.mode),
		"path", hs.path,
		"session", hs.sessionString())

	s := srv.hub.get(hs.path)

	switch hs.mode {
	case modePush:
		ok, seamless := s.claim(hs.sessionID, hs.hasSession())
		if !ok {
			logger.Warn("push rejected: path occupied", "peer", peer, "path", hs.path)
			_ = writeResponse(conn, statusOccupied)
			return
		}
		if err := writeResponse(conn, statusOK); err != nil {
			s.release()
			return
		}
		if seamless {
			_, gopBytes, gopMsgs, _ := s.snapshot()
			logger.Info("seamless reconnect",
				"peer", peer, "path", hs.path,
				"gop_bytes", gopBytes, "gop_msgs", gopMsgs)
		}
		srv.servePush(conn, s, peer, seamless)
		s.release()
		logger.Info("publisher disconnected", "peer", peer, "path", hs.path)

	case modePull:
		if err := writeResponse(conn, statusOK); err != nil {
			return
		}
		srv.servePull(conn, s, peer)
		logger.Info("subscriber disconnected", "peer", peer, "path", hs.path)
	}
}

func (srv *server) servePush(conn net.Conn, s *stream, peer string, seamless bool) {
	first := true
	var packets uint64
	var keyframes uint64
	var bytes uint64

	for {
		m, err := readMessage(conn)
		if err != nil {
			if err != io.EOF {
				logger.Warn("push read failed", "peer", peer, "path", s.path, "err", err)
			}
			logger.Debug("push ended",
				"peer", peer, "path", s.path,
				"packets", packets, "keyframes", keyframes, "bytes", bytes)
			return
		}

		if first {
			if m.mtype != msgHeader {
				logger.Warn("push first message is not a header",
					"peer", peer, "path", s.path, "type", fmt.Sprintf("0x%02x", m.mtype))
				return
			}
			if !seamless || s.header == nil || !equalFramed(s.header, m) {
				s.setHeader(m)
				logger.Debug("header set", "peer", peer, "path", s.path, "bytes", m.size)
			} else {
				logger.Debug("header unchanged on reconnect", "peer", peer, "path", s.path)
			}
			first = false
			continue
		}

		switch m.mtype {
		case msgHeader:
			s.setHeader(m)
			logger.Debug("header replaced", "peer", peer, "path", s.path, "bytes", m.size)
		case msgKey:
			s.publish(m)
			keyframes++
			packets++
			bytes += uint64(m.size)
		case msgPacket:
			s.publish(m)
			packets++
			bytes += uint64(m.size)
		default:
			logger.Warn("unknown message type",
				"peer", peer, "path", s.path, "type", fmt.Sprintf("0x%02x", m.mtype))
		}
	}
}

func equalFramed(a, b *message) bool {
	if a == nil || b == nil || len(a.framed) != len(b.framed) {
		return false
	}
	for i := range a.framed {
		if a.framed[i] != b.framed[i] {
			return false
		}
	}
	return true
}

func (srv *server) servePull(conn net.Conn, s *stream, peer string) {
	ch, header, gop, ok := s.subscribe()
	if !ok {
		logger.Warn("pull timed out waiting for publisher", "peer", peer, "path", s.path)
		return
	}
	defer s.unsubscribe(ch)

	logger.Debug("pull catch-up sending",
		"peer", peer, "path", s.path,
		"header_bytes", header.size, "gop_msgs", len(gop))

	if _, err := conn.Write(header.framed); err != nil {
		return
	}
	for _, m := range gop {
		if _, err := conn.Write(m.framed); err != nil {
			return
		}
	}
	for m := range ch {
		if _, err := conn.Write(m.framed); err != nil {
			return
		}
	}
}

func modeName(m byte) string {
	switch m {
	case modePush:
		return "push"
	case modePull:
		return "pull"
	default:
		return fmt.Sprintf("?%d", m)
	}
}

// --- main ---

func main() {
	addr := flag.String("addr", ":7777", "listen address")
	logLvl := flag.String("log", "info", "log level (debug|info|warn|error)")
	flag.Parse()

	lvl, err := parseLevel(*logLvl)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(lvl)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal("listen failed", "addr", *addr, "err", err)
	}
	logger.Info("smp listening", "addr", ln.Addr().String(), "level", *logLvl)

	srv := &server{hub: newHub()}
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept failed", "err", err)
			continue
		}
		go srv.handle(conn)
	}
}
