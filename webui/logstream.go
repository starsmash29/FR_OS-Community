package webui

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// GET /xdp/logs/stream: the XDP SNI filter's event log, live, as
// server-sent events (1.x's routes/xdp.py stream_logs). Each stream is
// one `tail -F` child, so they are bounded (review v0.2.0 R19): one per
// webUI session, fanned out to every tab of that session, and
// logStreamLimit of them per process; a tab past the cap gets one error
// frame and no child.

const (
	// logStreamLimit is LOG_STREAM_LIMIT.
	logStreamLimit = 8
	// logQueueMax is the frames a tab may have waiting: a tab that stops
	// reading loses the oldest ones, it doesn't block the stream or grow
	// the webUI's memory.
	logQueueMax = 256
	// logHeartbeat is the keep-alive interval, and so the bound on
	// noticing a closed tab on a quiet log.
	logHeartbeat = 15 * time.Second
	// logLineLimit is asyncio's StreamReader limit: a longer line ends
	// the stream.
	logLineLimit = 1 << 16
	keepalive    = ": keepalive\n\n"
)

// sniTail is _EVENTS_CMD: `-n 50` seeds the stream with recent events.
func (p Paths) sniTail() []string {
	return []string{"tail", "-n", "50", "-F", "--", p.at("/var/log/fr_os-sni/events.jsonl")}
}

// sseFrame is one event-log line as a frame, or "" when it is dropped:
// the line is forwarded verbatim, but only when it parses, so a cut
// line can't break the browser's JSON.parse.
func sseFrame(line string) string {
	if line == "" {
		return ""
	}
	if !pyJSONValid(line) {
		return ""
	}
	return "data: " + line + "\n\n"
}

// maxJSONDepth bounds the nesting pyJSONValid follows: deeper text is
// refused (1.x's json.loads raises RecursionError somewhere near its
// recursion limit, which ends the stream; decisions.md, 3c-2).
const maxJSONDepth = 512

// pyJSONValid is whether json.loads(text) parses: JSON as Python reads
// it, with NaN, Infinity and -Infinity, a name given twice, and lone
// surrogate escapes; only a value, between JSON whitespace.
func pyJSONValid(text string) bool {
	p := jsonScan{s: text}
	p.space()
	if !p.value(0) {
		return false
	}
	p.space()
	return p.i == len(p.s)
}

type jsonScan struct {
	s string
	i int
}

func (p *jsonScan) space() {
	for p.i < len(p.s) && strings.IndexByte(" \t\n\r", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *jsonScan) literal(word string) bool {
	if strings.HasPrefix(p.s[p.i:], word) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *jsonScan) value(depth int) bool {
	if p.i >= len(p.s) || depth > maxJSONDepth {
		return false
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		p.space()
		if p.literal("}") {
			return true
		}
		for {
			if p.i >= len(p.s) || p.s[p.i] != '"' || !p.str() {
				return false
			}
			p.space()
			if !p.literal(":") {
				return false
			}
			p.space()
			if !p.value(depth + 1) {
				return false
			}
			p.space()
			if p.literal("}") {
				return true
			}
			if !p.literal(",") {
				return false
			}
			p.space()
		}
	case c == '[':
		p.i++
		p.space()
		if p.literal("]") {
			return true
		}
		for {
			if !p.value(depth + 1) {
				return false
			}
			p.space()
			if p.literal("]") {
				return true
			}
			if !p.literal(",") {
				return false
			}
			p.space()
		}
	case c == '"':
		return p.str()
	case c == '-' && strings.HasPrefix(p.s[p.i:], "-Infinity"):
		p.i += len("-Infinity")
		return true
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	}
	return p.literal("true") || p.literal("false") || p.literal("null") || p.literal("NaN") ||
		p.literal("Infinity")
}

// str is a string from its opening quote: no raw control character,
// only JSON's escapes.
func (p *jsonScan) str() bool {
	p.i++
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return true
		case c < 0x20:
			return false
		case c == '\\':
			if p.i+1 >= len(p.s) {
				return false
			}
			e := p.s[p.i+1]
			if e == 'u' {
				if p.i+6 > len(p.s) {
					return false
				}
				for _, h := range []byte(p.s[p.i+2 : p.i+6]) {
					if !isHex(h) {
						return false
					}
				}
				p.i += 6
				continue
			}
			if strings.IndexByte(`"\\/bfnrt`, e) < 0 {
				return false
			}
			p.i += 2
		default:
			p.i++
		}
	}
	return false
}

// number is json's NUMBER_RE: -?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?.
func (p *jsonScan) number() bool {
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	p.literal("-")
	if !p.literal("0") && digits() == 0 {
		return false
	}
	if p.i+1 < len(p.s) && p.s[p.i] == '.' && p.s[p.i+1] >= '0' && p.s[p.i+1] <= '9' {
		p.i++
		digits()
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		save := p.i
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			p.i = save
		}
	}
	return true
}

func sseError(message string) string {
	return "data: {\"error\": " + config.PyJSONString(message) + "}\n\n"
}

// logTab is one browser tab's queue.
type logTab struct {
	frames []string
	ended  bool
	wake   chan struct{}
}

// logStream is one session's `tail -F`, shared by its tabs.
type logStream struct {
	key      string
	tabs     map[*logTab]bool
	finished bool
	started  bool
	cancel   context.CancelFunc
}

type logRegistry struct {
	mu      sync.Mutex
	streams map[string]*logStream
}

// offer queues a frame without blocking; a full queue loses its oldest.
// The caller holds the registry's lock.
func (t *logTab) offer(frame string) {
	if len(t.frames) >= logQueueMax {
		t.frames = t.frames[1:]
	}
	t.frames = append(t.frames, frame)
	t.signal()
}

func (t *logTab) signal() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (r *logRegistry) broadcast(st *logStream, frame string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st.finished {
		return
	}
	for t := range st.tabs {
		t.offer(frame)
	}
}

// end wakes every tab with the end and gives the session's slot back.
func (r *logRegistry) end(st *logStream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st.finished {
		return
	}
	st.finished = true
	for t := range st.tabs {
		t.ended = true
		t.signal()
	}
	if r.streams[st.key] == st {
		delete(r.streams, st.key)
	}
}

// subscribe is _acquire_stream and subscribe in one step: the session's
// stream (started when new) and a tab on it, or nil at the cap.
func (s *Server) subscribe(key string) (*logStream, *logTab) {
	r := &s.logs
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams == nil {
		r.streams = map[string]*logStream{}
	}
	st := r.streams[key]
	if st == nil || st.finished {
		if len(r.streams) >= logStreamLimit {
			return nil, nil
		}
		st = &logStream{key: key, tabs: map[*logTab]bool{}}
		r.streams[key] = st
	}
	tab := &logTab{wake: make(chan struct{}, 1)}
	st.tabs[tab] = true
	if !st.started {
		st.started = true
		ctx, cancel := context.WithCancel(context.Background())
		st.cancel = cancel
		go s.pump(ctx, st)
	}
	return st, tab
}

// unsubscribe: one tab went away; the last one ends the stream.
func (s *Server) unsubscribe(st *logStream, tab *logTab) {
	r := &s.logs
	r.mu.Lock()
	delete(st.tabs, tab)
	last := len(st.tabs) == 0 && !st.finished
	r.mu.Unlock()
	if last {
		st.cancel() // the pump ends the child, then the stream
	}
}

// pump owns the child: it reads the log and gives each frame to every
// tab, until the child ends, a line is too long, or the last tab goes.
func (s *Server) pump(ctx context.Context, st *logStream) {
	defer s.logs.end(st)
	stdout, stderr, stop, err := s.env.Follow(s.env.Paths.sniTail())
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			s.logs.broadcast(st, sseError("tail not found -- is coreutils installed?"))
		}
		return
	}
	var once sync.Once
	halt := func() { once.Do(stop) }
	defer halt()
	go func() {
		<-ctx.Done()
		halt()
	}()
	defer st.cancel()
	// tail -F keeps retrying a file it can't open and says why on
	// stderr: a missing file is normal before the logger first starts,
	// one this process may not read is a broken install, said once.
	go func() {
		lines := bufio.NewScanner(stderr)
		reported := false
		for lines.Scan() {
			if !reported && strings.Contains(lines.Text(), "Permission denied") {
				s.logs.broadcast(st, sseError("cannot read the SNI event log (permission denied)"))
				reported = true
			}
		}
	}()
	reader := bufio.NewReaderSize(stdout, logLineLimit+1)
	for {
		raw, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return // asyncio's LimitOverrunError: the stream ends
		}
		if len(raw) > 0 {
			if frame := sseFrame(strings.TrimRight(pyDecodeUTF8(raw), "\n")); frame != "" {
				s.logs.broadcast(st, frame)
			}
		}
		if err != nil {
			return // the child ended
		}
	}
}

// streamKey is the session behind the request, as the registry's key:
// the cookie is a bearer secret, so only its digest is kept.
func streamKey(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(sum[:])
}

func (s *Server) streamXDPLog(q *request) (*answer, error) {
	cookie := q.cookies[CookieName]
	if cookie == "" {
		return nil, &httpError{status: 401, detail: "Unauthorized"}
	}
	key := streamKey(cookie)
	a := &answer{status: 200}
	a.header("cache-control", "no-cache")
	a.header("x-accel-buffering", "no") // nginx: don't buffer an SSE stream
	a.header("content-type", "text/event-stream; charset=utf-8")
	a.stream = func(ctx context.Context, write func(string) bool) {
		st, tab := s.subscribe(key)
		if st == nil {
			write(sseError("live log stream limit reached (8) -- close a stream and reconnect"))
			return
		}
		defer s.unsubscribe(st, tab)
		timer := time.NewTimer(logHeartbeat)
		defer timer.Stop()
		for {
			s.logs.mu.Lock()
			frames, ended := tab.frames, tab.ended
			tab.frames = nil
			s.logs.mu.Unlock()
			for _, frame := range frames {
				if ctx.Err() != nil || !write(frame) {
					return
				}
			}
			if ended {
				return
			}
			if len(frames) > 0 {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(logHeartbeat)
			}
			select {
			case <-ctx.Done():
				return
			case <-tab.wake:
			case <-timer.C:
				if !write(keepalive) {
					return
				}
				timer.Reset(logHeartbeat)
			}
		}
	}
	return a, nil
}

// followProgram is Env.Follow on the router: the program runs until
// stop, which sends it SIGTERM and, after 5 s, SIGKILL.
func followProgram(argv []string) (io.Reader, io.Reader, func(), error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	stop := func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}
	return stdout, stderr, stop, nil
}
