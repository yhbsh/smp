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
	mdatSize := r.pos - r.mdatPos
	r.f.Seek(r.mdatPos, io.SeekStart)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(mdatSize))
	r.f.Write(b[:])
	r.f.Seek(r.pos, io.SeekStart)
	r.f.Write(r.moov())
	r.f.Close()
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

func (r *mp4Recorder) moov() []byte {
	var movieDur uint32
	var traks [][]byte
	for i := range r.tracks {
		t := &r.tracks[i]
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
	parts := [][]byte{mp4Mvhd(movieDur, uint32(len(r.tracks)+1))}
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
		streams, err := parseHeader(header)
		if err != nil {
			return nil, "", err
		}
		f, err := os.Create(fn)
		if err != nil {
			return nil, "", err
		}
		ftyp := mp4Ftyp()
		f.Write(ftyp)
		mdatPos := int64(len(ftyp))
		f.Write([]byte{0, 0, 0, 0, 'm', 'd', 'a', 't'})
		tracks := make([]trackState, len(streams))
		for i, si := range streams {
			tracks[i].info = si
		}
		return &mp4Recorder{f: f, tracks: tracks, mdatPos: mdatPos, pos: mdatPos + 8}, fn, nil

	default:
		return nil, "", fmt.Errorf("unknown record method %q (use mp4, ffmpeg, or smp)", method)
	}
}

// --- server ---

type server struct {
	hub          *hub
	recordDir    string
	recordMethod string
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
	var rec recorder
	var recFile string

	defer func() {
		if rec != nil {
			rec.stop()
			logger.Info("recording stopped", "file", recFile)
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

			if srv.recordDir != "" {
				r, fn, err := newRecorder(srv.recordMethod, srv.recordDir, s.path, m)
				if err != nil {
					logger.Warn("recording failed to start", "path", s.path, "err", err)
				} else {
					rec = r
					recFile = fn
					rec.write(m)
					logger.Info("recording started", "file", recFile)
				}
			}
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

		if rec != nil {
			rec.write(m)
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
	recordDir := flag.String("record", "", "directory to save recordings (empty=disabled)")
	recordMethod := flag.String("record-method", "mp4", "recording method: mp4, ffmpeg, smp")
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

	if *recordDir != "" {
		if err := os.MkdirAll(*recordDir, 0755); err != nil {
			logger.Fatal("cannot create record dir", "dir", *recordDir, "err", err)
		}
		logger.Info("recording enabled", "dir", *recordDir)
	}

	srv := &server{hub: newHub(), recordDir: *recordDir, recordMethod: *recordMethod}
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept failed", "err", err)
			continue
		}
		go srv.handle(conn)
	}
}
