package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReleaseVersionsCompareAsTuples(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		newer, parsed   bool
	}{
		{"9.9.9", "0.2.1", true, true},
		{"0.2.1", "0.2.1", false, true},
		{"0.10.0", "0.9.9", true, true},
		{"v1.0.0", "0.2.1", true, true},
		{"0.2.01", "0.2.1", false, true},
		{"99999999999999999999.0.0", "2.0.0", true, true},
		{"nightly", "0.2.1", false, false},
		{"0.2.1 ", "0.2.1", false, false},
	} {
		newer, parsed := newerVersion(c.latest, c.current)
		if newer != c.newer || parsed != c.parsed {
			t.Errorf("newerVersion(%q, %q) = %v, %v", c.latest, c.current, newer, parsed)
		}
	}
}

func TestCodenamesAreTheReleaseCycles(t *testing.T) {
	for version, want := range map[string]string{
		"0.2.1": "Ice Breaker", "1.0.0": "Ice Breaker", "v1.0.1": "Idun", "2.0.0": "Ivar",
		" 2.3.4\n": "Ivar", "5.0.0": "", "2.0": "", "": "",
	} {
		if got := codenameFor(version); got != want {
			t.Errorf("codenameFor(%q) = %q, want %q", version, got, want)
		}
	}
	if got := withCodename("2.0.0"); got != "2.0.0 “Ivar”" {
		t.Errorf("withCodename = %q", got)
	}
}

// The real fetch, against a local server: the headers GitHub asks for,
// the status passed on, and an answer too large refused unread.
func TestFetchReleaseBoundsTheAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "fr_os-update" {
			http.Error(w, "headers", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/big":
			w.Write([]byte(`{"body": "` + strings.Repeat("x", maxReleaseBytes) + `"}`))
		case "/missing":
			http.NotFound(w, r)
		default:
			w.Write([]byte(`{"tag_name": "v2.0.1"}`))
		}
	}))
	defer server.Close()
	status, body, err := fetchRelease(server.URL+"/latest", 5)
	if err != nil || status != 200 || string(body) != `{"tag_name": "v2.0.1"}` {
		t.Fatalf("latest: %d %q %v", status, body, err)
	}
	if status, _, err := fetchRelease(server.URL+"/missing", 5); err != nil || status != 404 {
		t.Fatalf("missing: %d %v", status, err)
	}
	if _, _, err := fetchRelease(server.URL+"/big", 5); err == nil {
		t.Fatal("an answer over the limit was read")
	}
}

// What the page says for an answer that isn't a release, through
// checkLatest with a fake fetch.
func TestCheckLatestRefusesWhatIsNotARelease(t *testing.T) {
	for body, want := range map[string]string{
		`{"tag_name": "v1", "tag_name": "v9.9.9"}`: "",
		`not json`: "invalid JSON from https://api.github.com/repos/o/n/releases/latest: ",
		"\xff":     "invalid JSON from https://api.github.com/repos/o/n/releases/latest: not UTF-8",
		`[1]`:      "unexpected release response from GitHub for o/n",
	} {
		s := &Server{env: Env{Fetch: func(string, float64) (int, []byte, error) { return 200, []byte(body), nil }}}
		result, message := s.checkLatest("2.0.0", "o/n")
		if !strings.HasPrefix(message, want) || (want == "") != (message == "") {
			t.Errorf("%q: message %q", body, message)
		}
		if want == "" && (result.Latest.Version != "9.9.9" || !result.UpdateAvailable) {
			t.Errorf("%q: %+v", body, result.Latest)
		}
	}
}
