package webui

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// json.loads's answers, from Python 3.11.
func TestLogLinesParseAsPythonsJSON(t *testing.T) {
	for _, c := range []struct {
		text string
		ok   bool
	}{
		{"{}", true}, {"[]", true}, {" {\"a\":1} ", true}, {"\t[1]\r", true}, {"NaN", true},
		{"-Infinity", true}, {"Infinity", true}, {"-NaN", false}, {"nan", false}, {"01", false},
		{"-", false}, {"-0", true}, {"1.", false}, {"1.5e", false}, {"1e5", true}, {"1E+2", true},
		{".5", false}, {"\"\\ud800\"", true}, {"\"\\x\"", false}, {"\"a\u0001\"", false},
		{"\"\\u12g4\"", false}, {"{\"a\":1,\"a\":2}", true}, {"{\"a\" 1}", false}, {"[1,]", false},
		{"{,}", false}, {"true", true}, {"tru", false}, {"null x", false}, {"\"\u00e9\"", true},
		{"\ufeff{}", false}, {"[1 2]", false}, {"{\"a\":[{\"b\":null}]}", true},
		{"\"unterminated", false}, {"", false}, {"  ", false}, {"0", true}, {"-1.25E-3", true},
		{"[NaN, Infinity, -Infinity]", true}, {"\"tab\there\"", false},
		{strings.Repeat("[", 600) + strings.Repeat("]", 600), false},
	} {
		if got := pyJSONValid(c.text); got != c.ok {
			t.Errorf("pyJSONValid(%q) = %v", c.text, got)
		}
	}
}

// followed is a fake tail -F that runs until stopped.
type followed struct {
	mu      sync.Mutex
	stopped int
	stderr  string
	writers []*io.PipeWriter
}

func (f *followed) follow([]string) (io.Reader, io.Reader, func(), error) {
	r, w := io.Pipe()
	f.mu.Lock()
	f.writers = append(f.writers, w)
	f.mu.Unlock()
	return r, strings.NewReader(f.stderr), func() {
		f.mu.Lock()
		f.stopped++
		f.mu.Unlock()
		w.Close()
	}, nil
}

func (f *followed) stops() int { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }

// tabFor opens one tab of a session's stream; its frames arrive on the
// channel, which closes when the tab's answer ends.
func tabFor(t *testing.T, s *Server, ctx context.Context, cookie string) <-chan string {
	t.Helper()
	a, err := s.streamXDPLog(&request{cookies: map[string]string{CookieName: cookie}})
	if err != nil {
		t.Fatal(err)
	}
	frames := make(chan string, 16)
	go func() {
		defer close(frames)
		a.stream(ctx, func(piece string) bool { frames <- piece; return true })
	}()
	return frames
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *Server) streamCount() int {
	s.logs.mu.Lock()
	defer s.logs.mu.Unlock()
	return len(s.logs.streams)
}

// Review v0.2.0 R19: one child per session, at most logStreamLimit of
// them; a tab past the cap gets one error frame and no child, and the
// last tab to go stops its session's child.
func TestLiveLogStreamsAreCapped(t *testing.T) {
	fake := &followed{}
	s := &Server{env: Env{Follow: fake.follow}}
	ctx, cancel := context.WithCancel(context.Background())
	var tabs []<-chan string
	for i := range logStreamLimit {
		tabs = append(tabs, tabFor(t, s, ctx, "session-"+string(rune('a'+i))))
	}
	// A second tab of a session shares its child.
	second, cancelSecond := context.WithCancel(context.Background())
	shared := tabFor(t, s, second, "session-a")
	waitFor(t, "the streams", func() bool { return s.streamCount() == logStreamLimit })
	over := tabFor(t, s, context.Background(), "session-z")
	if frame := <-over; frame != `data: {"error": "live log stream limit reached (8) -- close a stream and reconnect"}`+"\n\n" {
		t.Fatalf("over the cap: %q", frame)
	}
	if _, open := <-over; open {
		t.Fatal("the tab over the cap stayed open")
	}
	children := func() int { fake.mu.Lock(); defer fake.mu.Unlock(); return len(fake.writers) }
	waitFor(t, "the children", func() bool { return children() == logStreamLimit })
	time.Sleep(10 * time.Millisecond)
	if n := children(); n != logStreamLimit {
		t.Fatalf("%d children for %d sessions", n, logStreamLimit)
	}
	cancelSecond()
	for range shared {
	}
	if fake.stops() != 0 || s.streamCount() != logStreamLimit {
		t.Fatal("a session's child stopped while one of its tabs was open")
	}
	// A frame reaches the session's tab (whichever child is its).
	for _, w := range fake.writers {
		go w.Write([]byte(`{"sni": "a.example"}` + "\n"))
	}
	if frame := <-tabs[0]; frame != `data: {"sni": "a.example"}`+"\n\n" {
		t.Fatalf("frame: %q", frame)
	}
	cancel()
	for _, tab := range tabs {
		for range tab {
		}
	}
	waitFor(t, "the children to stop", func() bool { return fake.stops() == logStreamLimit && s.streamCount() == 0 })
}

// A log the webUI may not read is said once, not left silent.
func TestLiveLogSaysWhenTheLogCantBeRead(t *testing.T) {
	line := "tail: cannot open '/var/log/fr_os-sni/events.jsonl' for reading: Permission denied\n"
	fake := &followed{stderr: line + line}
	s := &Server{env: Env{Follow: fake.follow}}
	tab := tabFor(t, s, context.Background(), "session")
	if frame := <-tab; frame != `data: {"error": "cannot read the SNI event log (permission denied)"}`+"\n\n" {
		t.Fatalf("frame: %q", frame)
	}
	waitFor(t, "the child", func() bool { fake.mu.Lock(); defer fake.mu.Unlock(); return len(fake.writers) == 1 })
	fake.writers[0].Close()
	var rest []string
	for frame := range tab {
		rest = append(rest, frame)
	}
	if len(rest) != 0 {
		t.Fatalf("more frames: %q", rest)
	}
}
