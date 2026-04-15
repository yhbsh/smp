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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

// --- recording ---

type recorder interface {
	write(m *message)
	stop()
}

// SMP header/packet parsing for native MP4 muxing.

const (
	avCodecH264  = 27
	avCodecAAC   = 86018
	avMediaVideo = 0
	avMediaAudio = 1
)

type streamInfo struct {
	codecID    uint32
	codecType  uint8
	tbNum      uint32
	tbDen      uint32
	width      uint32
	height     uint32
	sampleRate uint32
	channels   uint8
	extradata  []byte
}

func parseHeader(m *message) ([]streamInfo, error) {
	p := m.framed[4:]
	if len(p) < 3 || p[0] != msgHeader || p[1] != 1 {
		return nil, errors.New("invalid smp header")
	}
	n, off := int(p[2]), 3
	out := make([]streamInfo, 0, n)
	for i := 0; i < n; i++ {
		if off+30 > len(p) {
			return nil, fmt.Errorf("truncated stream %d", i)
		}
		si := streamInfo{
			codecID:    binary.BigEndian.Uint32(p[off:]),
			codecType:  p[off+4],
			tbNum:      binary.BigEndian.Uint32(p[off+5:]),
			tbDen:      binary.BigEndian.Uint32(p[off+9:]),
			width:      binary.BigEndian.Uint32(p[off+13:]),
			height:     binary.BigEndian.Uint32(p[off+17:]),
			sampleRate: binary.BigEndian.Uint32(p[off+21:]),
			channels:   p[off+25],
		}
		edSz := int(binary.BigEndian.Uint32(p[off+26:]))
		off += 30
		if off+edSz > len(p) {
			return nil, fmt.Errorf("truncated extradata %d", i)
		}
		if edSz > 0 {
			si.extradata = append([]byte{}, p[off:off+edSz]...)
			off += edSz
		}
		out = append(out, si)
	}
	return out, nil
}

type packetInfo struct {
	streamIdx uint8
	pts       int64
	dts       int64
	duration  int64
	keyframe  bool
	data      []byte
}

func parsePacket(m *message) packetInfo {
	p := m.framed[4:]
	sz := binary.BigEndian.Uint32(p[26:])
	return packetInfo{
		keyframe:  p[0] == msgKey,
		streamIdx: p[1],
		pts:       int64(binary.BigEndian.Uint64(p[2:])),
		dts:       int64(binary.BigEndian.Uint64(p[10:])),
		duration:  int64(binary.BigEndian.Uint64(p[18:])),
		data:      p[30 : 30+sz],
	}
}

// --- recording: smp (raw dump) ---

type smpRecorder struct{ f *os.File }

func (r *smpRecorder) write(m *message) { r.f.Write(m.framed) }
func (r *smpRecorder) stop()            { r.f.Close() }

// --- recording: ffmpeg subprocess ---

type ffmpegRecorder struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func (r *ffmpegRecorder) write(m *message) { r.stdin.Write(m.framed) }
func (r *ffmpegRecorder) stop()            { r.stdin.Close(); r.cmd.Wait() }

// --- recording: native mp4 muxer ---

type sampleMeta struct {
	offset int64
	size   uint32
	dts    int64
	pts    int64
	dur    int64
	key    bool
}

type trackState struct {
	info    streamInfo
	samples []sampleMeta
}

type mp4Recorder struct {
	f       *os.File
	tracks  []trackState
	mdatPos int64
	pos     int64
}

func (r *mp4Recorder) write(m *message) {
	if m.mtype == msgHeader {
		return
	}
	pkt := parsePacket(m)
	idx := int(pkt.streamIdx)
	if idx >= len(r.tracks) {
		return
	}
	r.tracks[idx].samples = append(r.tracks[idx].samples, sampleMeta{
		offset: r.pos, size: uint32(len(pkt.data)),
		dts: pkt.dts, pts: pkt.pts, dur: pkt.duration, key: pkt.keyframe,
	})
	r.f.Write(pkt.data)
	r.pos += int64(len(pkt.data))
}

func (r *mp4Recorder) stop() {
	writeFaststart(r.f, r.tracks, r.mdatPos, r.pos)
}

func (r *mp4Recorder) stopRaw() {
	mdatSize := r.pos - r.mdatPos
	r.f.Seek(r.mdatPos, io.SeekStart)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(mdatSize))
	r.f.Write(b[:])
	r.f.Seek(r.pos, io.SeekStart)
	r.f.Write(buildMoov(r.tracks))
	r.f.Close()
}

func writeFaststart(f *os.File, tracks []trackState, mdatPos, pos int64) {
	mdatDataLen := pos - (mdatPos + 8)
	f.Seek(mdatPos+8, io.SeekStart)
	mdatData := make([]byte, mdatDataLen)
	io.ReadFull(f, mdatData)

	moov := buildMoov(tracks)
	moovSize := int64(len(moov))
	for i := range tracks {
		for j := range tracks[i].samples {
			tracks[i].samples[j].offset += moovSize
		}
	}
	moov = buildMoov(tracks)

	ftypLen := int64(len(mp4Ftyp()))
	mdatTotal := pos - mdatPos
	f.Seek(ftypLen, io.SeekStart)
	f.Write(moov)
	var mdatHdr [8]byte
	binary.BigEndian.PutUint32(mdatHdr[:4], uint32(mdatTotal))
	copy(mdatHdr[4:], "mdat")
	f.Write(mdatHdr[:])
	f.Write(mdatData)
	f.Truncate(ftypLen + moovSize + mdatTotal)
	f.Close()
}

func newMp4Recorder(filename string, header *message) (*mp4Recorder, error) {
	streams, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	ftyp := mp4Ftyp()
	f.Write(ftyp)
	mdatPos := int64(len(ftyp))
	f.Write([]byte{0, 0, 0, 0, 'm', 'd', 'a', 't'})
	tracks := make([]trackState, len(streams))
	for i, si := range streams {
		tracks[i].info = si
	}
	return &mp4Recorder{f: f, tracks: tracks, mdatPos: mdatPos, pos: mdatPos + 8}, nil
}

// mp4 box helpers

func bx(t string, parts ...[]byte) []byte {
	n := 8
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	out = binary.BigEndian.AppendUint32(out, uint32(n))
	out = append(out, t...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func fbx(t string, ver byte, fl uint32, parts ...[]byte) []byte {
	vf := binary.BigEndian.AppendUint32(nil, (uint32(ver)<<24)|(fl&0xFFFFFF))
	all := make([][]byte, 0, len(parts)+1)
	all = append(all, vf)
	all = append(all, parts...)
	return bx(t, all...)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// mp4 box builders

func mp4Ftyp() []byte {
	return bx("ftyp", []byte("isom"), u32(0x200), []byte("isomiso2avc1mp41"))
}

func mp4Mvhd(dur, nextTrack uint32) []byte {
	b := make([]byte, 96)
	binary.BigEndian.PutUint32(b[8:], 1000)
	binary.BigEndian.PutUint32(b[12:], dur)
	binary.BigEndian.PutUint32(b[16:], 0x00010000)
	binary.BigEndian.PutUint16(b[20:], 0x0100)
	binary.BigEndian.PutUint32(b[32:], 0x00010000)
	binary.BigEndian.PutUint32(b[48:], 0x00010000)
	binary.BigEndian.PutUint32(b[64:], 0x40000000)
	binary.BigEndian.PutUint32(b[92:], nextTrack)
	return fbx("mvhd", 0, 0, b)
}

func mp4Tkhd(id, dur uint32, si streamInfo) []byte {
	b := make([]byte, 80)
	binary.BigEndian.PutUint32(b[8:], id)
	binary.BigEndian.PutUint32(b[16:], dur)
	if si.codecType == avMediaAudio {
		binary.BigEndian.PutUint16(b[32:], 0x0100)
	}
	binary.BigEndian.PutUint32(b[36:], 0x00010000)
	binary.BigEndian.PutUint32(b[52:], 0x00010000)
	binary.BigEndian.PutUint32(b[68:], 0x40000000)
	binary.BigEndian.PutUint32(b[72:], si.width<<16)
	binary.BigEndian.PutUint32(b[76:], si.height<<16)
	return fbx("tkhd", 0, 3, b)
}

func mp4Mdhd(timescale, dur uint32) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint32(b[8:], timescale)
	binary.BigEndian.PutUint32(b[12:], dur)
	binary.BigEndian.PutUint16(b[16:], 0x55C4) // "und"
	return fbx("mdhd", 0, 0, b)
}

func mp4Hdlr(handler, name string) []byte {
	b := make([]byte, 20)
	copy(b[4:], handler)
	return fbx("hdlr", 0, 0, b, append([]byte(name), 0))
}

func mp4Dinf() []byte {
	return bx("dinf", fbx("dref", 0, 0, u32(1), fbx("url ", 0, 1)))
}

func mp4Avc1(si streamInfo) []byte {
	b := make([]byte, 78)
	binary.BigEndian.PutUint16(b[6:], 1)
	binary.BigEndian.PutUint16(b[24:], uint16(si.width))
	binary.BigEndian.PutUint16(b[26:], uint16(si.height))
	binary.BigEndian.PutUint32(b[28:], 0x00480000)
	binary.BigEndian.PutUint32(b[32:], 0x00480000)
	binary.BigEndian.PutUint16(b[40:], 1)
	binary.BigEndian.PutUint16(b[74:], 0x0018)
	binary.BigEndian.PutUint16(b[76:], 0xFFFF)
	return bx("avc1", b, bx("avcC", si.extradata))
}

func mp4Esds(asc []byte) []byte {
	dsi := append([]byte{0x05, byte(len(asc))}, asc...)
	dcd := append([]byte{0x04, byte(13 + len(dsi)),
		0x40, 0x15, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}, dsi...)
	esBody := append([]byte{0x00, 0x00, 0x00}, dcd...)
	esBody = append(esBody, 0x06, 0x01, 0x02)
	es := append([]byte{0x03, byte(len(esBody))}, esBody...)
	return fbx("esds", 0, 0, es)
}

func mp4Mp4a(si streamInfo) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[6:], 1)
	binary.BigEndian.PutUint16(b[16:], uint16(si.channels))
	binary.BigEndian.PutUint16(b[18:], 16)
	binary.BigEndian.PutUint32(b[24:], si.sampleRate<<16)
	return bx("mp4a", b, mp4Esds(si.extradata))
}

func mp4Stsd(si streamInfo) []byte {
	var entry []byte
	switch si.codecID {
	case avCodecH264:
		entry = mp4Avc1(si)
	case avCodecAAC:
		entry = mp4Mp4a(si)
	default:
		return fbx("stsd", 0, 0, u32(0))
	}
	return fbx("stsd", 0, 0, u32(1), entry)
}

func mp4Stts(samples []sampleMeta) []byte {
	type run struct{ count, delta uint32 }
	var runs []run
	for _, s := range samples {
		d := uint32(s.dur)
		if len(runs) > 0 && runs[len(runs)-1].delta == d {
			runs[len(runs)-1].count++
		} else {
			runs = append(runs, run{1, d})
		}
	}
	b := u32(uint32(len(runs)))
	for _, r := range runs {
		b = append(b, u32(r.count)...)
		b = append(b, u32(r.delta)...)
	}
	return fbx("stts", 0, 0, b)
}

func mp4Ctts(samples []sampleMeta) []byte {
	need := false
	for _, s := range samples {
		if s.pts != s.dts {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	b := u32(uint32(len(samples)))
	for _, s := range samples {
		b = append(b, u32(1)...)
		b = append(b, u32(uint32(int32(s.pts-s.dts)))...)
	}
	return fbx("ctts", 1, 0, b)
}

func mp4Stsz(samples []sampleMeta) []byte {
	b := u32(0)
	b = append(b, u32(uint32(len(samples)))...)
	for _, s := range samples {
		b = append(b, u32(s.size)...)
	}
	return fbx("stsz", 0, 0, b)
}

func mp4Stsc() []byte {
	return fbx("stsc", 0, 0, u32(1), u32(1), u32(1), u32(1))
}

func mp4Co64(samples []sampleMeta) []byte {
	b := u32(uint32(len(samples)))
	for _, s := range samples {
		b = append(b, u64(uint64(s.offset))...)
	}
	return fbx("co64", 0, 0, b)
}

func mp4Stss(samples []sampleMeta) []byte {
	var syncs []uint32
	for i, s := range samples {
		if s.key {
			syncs = append(syncs, uint32(i+1))
		}
	}
	if len(syncs) == 0 || len(syncs) == len(samples) {
		return nil
	}
	b := u32(uint32(len(syncs)))
	for _, n := range syncs {
		b = append(b, u32(n)...)
	}
	return fbx("stss", 0, 0, b)
}

func buildMoov(allTracks []trackState) []byte {
	var movieDur uint32
	var traks [][]byte
	for i := range allTracks {
		t := &allTracks[i]
		if len(t.samples) == 0 {
			continue
		}
		ts := t.info.tbDen
		first, last := t.samples[0], t.samples[len(t.samples)-1]
		durTS := uint32(last.dts + last.dur - first.dts)
		durMovie := uint32(float64(durTS) * 1000 / float64(ts))
		if durMovie > movieDur {
			movieDur = durMovie
		}
		si := t.info
		hdlrType, hdlrName := "vide", "VideoHandler"
		var mhd []byte
		if si.codecType == avMediaAudio {
			hdlrType, hdlrName = "soun", "SoundHandler"
			mhd = fbx("smhd", 0, 0, make([]byte, 4))
		} else {
			mhd = fbx("vmhd", 0, 1, make([]byte, 8))
		}
		stblParts := [][]byte{mp4Stsd(si), mp4Stts(t.samples)}
		if ctts := mp4Ctts(t.samples); ctts != nil {
			stblParts = append(stblParts, ctts)
		}
		stblParts = append(stblParts, mp4Stsc(), mp4Stsz(t.samples), mp4Co64(t.samples))
		if stss := mp4Stss(t.samples); stss != nil {
			stblParts = append(stblParts, stss)
		}
		traks = append(traks, bx("trak",
			mp4Tkhd(uint32(i+1), durMovie, si),
			bx("mdia",
				mp4Mdhd(ts, durTS),
				mp4Hdlr(hdlrType, hdlrName),
				bx("minf", mhd, mp4Dinf(), bx("stbl", stblParts...)),
			),
		))
	}
	parts := [][]byte{mp4Mvhd(movieDur, uint32(len(allTracks)+1))}
	parts = append(parts, traks...)
	return bx("moov", parts...)
}

// --- recording: factory ---

func newRecorder(method, dir, streamPath string, header *message) (recorder, string, error) {
	ts := time.Now().Format("20060102_150405")
	name := strings.ReplaceAll(strings.TrimPrefix(streamPath, "/"), "/", "_")
	base := filepath.Join(dir, "recording_"+name+"_"+ts)

	switch method {
	case "smp":
		fn := base + ".smp"
		f, err := os.Create(fn)
		if err != nil {
			return nil, "", err
		}
		return &smpRecorder{f: f}, fn, nil

	case "ffmpeg":
		fn := base + ".mp4"
		cmd := exec.Command("ffmpeg",
			"-f", "smp", "-i", "pipe:0",
			"-c", "copy", "-movflags", "+faststart",
			"-y", fn)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, "", err
		}
		if err := cmd.Start(); err != nil {
			stdin.Close()
			return nil, "", err
		}
		return &ffmpegRecorder{cmd: cmd, stdin: stdin}, fn, nil

	case "mp4":
		fn := base + ".mp4"
		rec, err := newMp4Recorder(fn, header)
		if err != nil {
			return nil, "", err
		}
		return rec, fn, nil

	default:
		return nil, "", fmt.Errorf("unknown record method %q (use mp4, ffmpeg, or smp)", method)
	}
}

// --- segmented recorder ---

const segDuration = 10 * time.Second

type segmentInfo struct {
	filename string
	created  time.Time
	tracks   []trackState
}

type segRecorder struct {
	dir      string
	path     string
	header   *message
	segments []segmentInfo
	current  *mp4Recorder
	curStart time.Time
	segCount int
	mu       sync.Mutex
}

func newSegRecorder(dir, path string, header *message) *segRecorder {
	sr := &segRecorder{dir: dir, path: path, header: header}
	sr.startNewSegment()
	return sr
}

func (sr *segRecorder) write(m *message) {
	if m.mtype == msgHeader {
		return
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if sr.current == nil {
		return
	}
	if m.mtype == msgKey && time.Since(sr.curStart) >= segDuration {
		sr.cutSegment()
	}
	sr.current.write(m)
}

func (sr *segRecorder) cutSegment() {
	if sr.current == nil {
		return
	}
	hasSamples := false
	for _, t := range sr.current.tracks {
		if len(t.samples) > 0 {
			hasSamples = true
			break
		}
	}
	if !hasSamples {
		sr.current.f.Close()
		os.Remove(sr.current.f.Name())
		sr.startNewSegment()
		return
	}
	tracks := make([]trackState, len(sr.current.tracks))
	for i, t := range sr.current.tracks {
		tracks[i].info = t.info
		tracks[i].samples = make([]sampleMeta, len(t.samples))
		copy(tracks[i].samples, t.samples)
	}
	sr.segments = append(sr.segments, segmentInfo{
		filename: sr.current.f.Name(),
		created:  sr.curStart,
		tracks:   tracks,
	})
	sr.current.stopRaw()
	sr.startNewSegment()
}

func (sr *segRecorder) startNewSegment() {
	name := fmt.Sprintf("seg_%s_%03d",
		strings.ReplaceAll(strings.TrimPrefix(sr.path, "/"), "/", "_"),
		sr.segCount)
	sr.segCount++
	fn := filepath.Join(sr.dir, name+".mp4")
	rec, err := newMp4Recorder(fn, sr.header)
	if err != nil {
		logger.Warn("failed to start segment", "path", sr.path, "err", err)
		sr.current = nil
		return
	}
	sr.current = rec
	sr.curStart = time.Now()
}

func (sr *segRecorder) finalize() (string, error) {
	sr.mu.Lock()
	sr.cutSegment()
	segs := sr.segments
	sr.segments = nil
	sr.mu.Unlock()

	if len(segs) == 0 {
		return "", errors.New("no segments")
	}

	ts := time.Now().Format("20060102_150405")
	name := strings.ReplaceAll(strings.TrimPrefix(sr.path, "/"), "/", "_")
	out := filepath.Join(sr.dir, "recording_"+name+"_"+ts+".mp4")

	if err := mergeSegments(segs, out); err != nil {
		return "", err
	}
	for _, seg := range segs {
		os.Remove(seg.filename)
	}
	return out, nil
}

func (sr *segRecorder) clip(seconds float64) (string, error) {
	sr.mu.Lock()
	sr.cutSegment()
	cutoff := time.Now().Add(-time.Duration(seconds * float64(time.Second)))
	var clipSegs []segmentInfo
	for _, seg := range sr.segments {
		if seg.created.After(cutoff) {
			clipSegs = append(clipSegs, seg)
		}
	}
	sr.mu.Unlock()

	if len(clipSegs) == 0 {
		return "", errors.New("no data in requested time range")
	}

	ts := time.Now().Format("20060102_150405")
	name := strings.ReplaceAll(strings.TrimPrefix(sr.path, "/"), "/", "_")
	out := filepath.Join(sr.dir, "clip_"+name+"_"+ts+".mp4")

	if err := mergeSegments(clipSegs, out); err != nil {
		return "", err
	}
	return out, nil
}

// mergeSegments combines multiple segment files into one faststart MP4.
// Segment files have layout: ftyp(32) | mdat(8+data) | moov.
// Sample offsets in trackState point into the segment file (data starts at 40).
func mergeSegments(segs []segmentInfo, outPath string) error {
	if len(segs) == 0 {
		return errors.New("no segments")
	}

	// Compute data length per segment and build merged tracks.
	merged := make([]trackState, len(segs[0].tracks))
	for i := range merged {
		merged[i].info = segs[0].tracks[i].info
	}

	type segRange struct{ start, length int64 }
	ranges := make([]segRange, len(segs))

	var totalData int64
	for si, seg := range segs {
		var maxEnd int64
		for _, t := range seg.tracks {
			for _, s := range t.samples {
				if end := s.offset + int64(s.size); end > maxEnd {
					maxEnd = end
				}
			}
		}
		dataLen := maxEnd - 40
		if dataLen < 0 {
			dataLen = 0
		}
		ranges[si] = segRange{start: totalData, length: dataLen}

		for ti, t := range seg.tracks {
			for _, s := range t.samples {
				merged[ti].samples = append(merged[ti].samples, sampleMeta{
					offset: totalData + (s.offset - 40), // relative to merged mdat start
					size:   s.size,
					dts:    s.dts,
					pts:    s.pts,
					dur:    s.dur,
					key:    s.key,
				})
			}
		}
		totalData += dataLen
	}

	// Fix durations at segment boundaries using absolute DTS.
	for ti := range merged {
		samples := merged[ti].samples
		for i := 0; i < len(samples)-1; i++ {
			samples[i].dur = samples[i+1].dts - samples[i].dts
		}
	}

	// Build moov to learn its size, then shift offsets for faststart.
	moov := buildMoov(merged)
	moovSize := int64(len(moov))
	base := int64(len(mp4Ftyp())) + moovSize + 8 // ftyp + moov + mdat header
	for ti := range merged {
		for j := range merged[ti].samples {
			merged[ti].samples[j].offset += base
		}
	}
	moov = buildMoov(merged)

	// Write output file: ftyp | moov | mdat header | data from each segment.
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	out.Write(mp4Ftyp())
	out.Write(moov)

	var mdatHdr [8]byte
	binary.BigEndian.PutUint32(mdatHdr[:4], uint32(8+totalData))
	copy(mdatHdr[4:], "mdat")
	out.Write(mdatHdr[:])

	for si, seg := range segs {
		f, err := os.Open(seg.filename)
		if err != nil {
			return err
		}
		f.Seek(40, io.SeekStart)
		io.CopyN(out, f, ranges[si].length)
		f.Close()
	}
	return nil
}

// --- server ---

type server struct {
	hub *hub
	dir string
	tm  *taskManager
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
	var sr *segRecorder

	defer func() {
		if sr != nil {
			srv.tm.mu.Lock()
			delete(srv.tm.autoRecs, s.path)
			srv.tm.mu.Unlock()

			go func() {
				merged, err := sr.finalize()
				if err != nil {
					logger.Error("auto-record finalize failed", "path", s.path, "err", err)
					return
				}
				logger.Info("auto-record finalized", "path", s.path, "file", merged)
				s3Key := "recordings/" + filepath.Base(merged)
				s3URL, err := uploadToS3(merged, s3Key)
				if err != nil {
					logger.Error("auto-record upload failed", "file", merged, "err", err)
				} else {
					os.Remove(merged)
					logger.Info("auto-record uploaded", "url", s3URL)
				}
			}()
		}
	}()

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

			sr = newSegRecorder(srv.dir, s.path, m)
			srv.tm.mu.Lock()
			srv.tm.autoRecs[s.path] = sr
			srv.tm.mu.Unlock()
			logger.Info("auto-record started", "peer", peer, "path", s.path)
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

		if sr != nil {
			sr.write(m)
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

// --- recording tasks ---

type taskState string

const (
	stateRecording taskState = "recording"
	stateUploading taskState = "uploading"
	stateDone      taskState = "done"
	stateFailed    taskState = "failed"

	defaultMaxDuration = 3600
	maxMaxDuration     = 14400 // 4 hours hard cap
)

type recordTask struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	State     taskState `json:"state"`
	StartedAt time.Time `json:"started_at"`
	Filename  string    `json:"filename,omitempty"`
	S3Path    string    `json:"s3_path,omitempty"`
	Error     string    `json:"error,omitempty"`

	rec    recorder
	stopCh chan struct{}
	st     *stream
	subCh  chan *message
}

type taskManager struct {
	mu       sync.Mutex
	tasks    map[string]*recordTask
	autoRecs map[string]*segRecorder
	hub      *hub
	dir      string
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (tm *taskManager) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Path        string `json:"path"`
		Method      string `json:"method"`
		MaxDuration int    `json:"max_duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.Path == "" {
		http.Error(w, `{"error":"path required"}`, 400)
		return
	}
	if req.Method == "" {
		req.Method = "mp4"
	}
	if req.MaxDuration <= 0 {
		req.MaxDuration = defaultMaxDuration
	}
	if req.MaxDuration > maxMaxDuration {
		req.MaxDuration = maxMaxDuration
	}

	s := tm.hub.get(req.Path)
	ch, header, gop, ok := s.subscribe()
	if !ok {
		http.Error(w, `{"error":"no publisher on path or timed out"}`, 404)
		return
	}

	rec, filename, err := newRecorder(req.Method, tm.dir, req.Path, header)
	if err != nil {
		s.unsubscribe(ch)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}

	rec.write(header)
	for _, m := range gop {
		rec.write(m)
	}

	id := randomID()
	task := &recordTask{
		ID: id, Path: req.Path, Method: req.Method,
		State: stateRecording, StartedAt: time.Now(),
		Filename: filename,
		rec:      rec, stopCh: make(chan struct{}), st: s, subCh: ch,
	}

	tm.mu.Lock()
	tm.tasks[id] = task
	tm.mu.Unlock()

	go tm.recordLoop(task, time.Duration(req.MaxDuration)*time.Second)

	logger.Info("recording started", "task", id, "path", req.Path, "file", filename)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"task_id": id})
}

func (tm *taskManager) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		TaskID string `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	tm.mu.Lock()
	task, ok := tm.tasks[req.TaskID]
	tm.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"task not found"}`, 404)
		return
	}
	if task.State != stateRecording {
		http.Error(w, fmt.Sprintf(`{"error":"task not recording, state=%s"}`, task.State), 409)
		return
	}

	close(task.stopCh)
	logger.Info("recording stop requested", "task", req.TaskID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"task_id": req.TaskID, "state": "stopping"})
}

func (tm *taskManager) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	tm.mu.Lock()
	out := make([]*recordTask, 0, len(tm.tasks))
	for _, t := range tm.tasks {
		out = append(out, t)
	}
	tm.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (tm *taskManager) handleClip(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Path    string  `json:"path"`
		Seconds float64 `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.Path == "" || req.Seconds <= 0 {
		http.Error(w, `{"error":"path and seconds required"}`, 400)
		return
	}

	tm.mu.Lock()
	sr, ok := tm.autoRecs[req.Path]
	tm.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"no active publisher on path"}`, 404)
		return
	}

	clipPath, err := sr.clip(req.Seconds)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}

	s3Key := "clips/" + filepath.Base(clipPath)
	s3URL, err := uploadToS3(clipPath, s3Key)
	os.Remove(clipPath)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), 500)
		return
	}

	logger.Info("clip created", "path", req.Path, "seconds", req.Seconds, "url", s3URL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"s3_path": s3URL})
}

func (tm *taskManager) recordLoop(task *recordTask, maxDur time.Duration) {
	timer := time.NewTimer(maxDur)
	defer timer.Stop()

	for {
		select {
		case m, ok := <-task.subCh:
			if !ok {
				goto stop
			}
			task.rec.write(m)
		case <-timer.C:
			logger.Warn("recording auto-stopped (max duration)", "task", task.ID, "path", task.Path)
			goto stop
		case <-task.stopCh:
			goto stop
		}
	}

stop:
	task.st.unsubscribe(task.subCh)
	task.rec.stop()

	tm.mu.Lock()
	task.State = stateUploading
	tm.mu.Unlock()
	logger.Info("recording stopped, uploading", "task", task.ID, "file", task.Filename)

	s3Key := "recordings/" + filepath.Base(task.Filename)
	s3URL, err := uploadToS3(task.Filename, s3Key)

	tm.mu.Lock()
	if err != nil {
		task.State = stateFailed
		task.Error = err.Error()
		logger.Error("s3 upload failed", "task", task.ID, "err", err)
	} else {
		task.State = stateDone
		task.S3Path = s3URL
		os.Remove(task.Filename)
		logger.Info("recording uploaded", "task", task.ID, "url", s3URL)
	}
	tm.mu.Unlock()
}

func (tm *taskManager) serve(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/record/start", tm.handleStart)
	mux.HandleFunc("/record/stop", tm.handleStop)
	mux.HandleFunc("/record/tasks", tm.handleTasks)
	mux.HandleFunc("/record/clip", tm.handleClip)
	logger.Info("api listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatal("api listen failed", "err", err)
	}
}

// --- s3 upload ---

func uploadToS3(filePath, s3Key string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")

	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", awsBucket, awsRegion)
	endpoint := fmt.Sprintf("https://%s/%s", host, s3Key)

	ct := "application/octet-stream"
	if strings.HasSuffix(filePath, ".mp4") {
		ct = "video/mp4"
	}

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\n",
		ct, host, datetime)
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := fmt.Sprintf("PUT\n/%s\n\n%s\n%s\nUNSIGNED-PAYLOAD", s3Key, canonicalHeaders, signedHeaders)

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", date, awsRegion)
	hash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", datetime, scope, hex.EncodeToString(hash[:]))

	kDate := hmacSHA256([]byte("AWS4"+awsSecretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(awsRegion))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	sig := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		awsAccessKeyID, scope, signedHeaders, sig)

	req, _ := http.NewRequest("PUT", endpoint, f)
	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	req.Header.Set("X-Amz-Date", datetime)
	req.Header.Set("Authorization", auth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("s3: %d %s", resp.StatusCode, string(body))
	}

	return s3Key, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// --- main ---

func main() {
	addr := flag.String("addr", ":7777", "listen address")
	apiAddr := flag.String("api", ":7778", "HTTP API address for recording control")
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

	h := newHub()

	dir := "recordings"
	os.MkdirAll(dir, 0755)
	tm := &taskManager{tasks: make(map[string]*recordTask), autoRecs: make(map[string]*segRecorder), hub: h, dir: dir}
	go tm.serve(*apiAddr)

	srv := &server{hub: h, dir: dir, tm: tm}
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept failed", "err", err)
			continue
		}
		go srv.handle(conn)
	}
}
