package apply

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
)

// listServer is a blocklist server on a real socket: /hosts and
// /malware answer lists, /gone a 404, /moved a redirect to /hosts, and
// /huge more than a download may hold.
func listServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "fr_os-adblock" {
			http.Error(w, "user agent "+ua, http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/hosts":
			fmt.Fprint(w, "# list\n0.0.0.0 ads.example Tracker.Example\n0.0.0.0 cdn.good.example\n127.0.0.1 localhost\n")
		case "/malware":
			fmt.Fprint(w, "evil.example\nuse-application-dns.net\n")
		case "/moved":
			http.Redirect(w, r, "/hosts", http.StatusFound)
		case "/huge":
			chunk := strings.Repeat("0.0.0.0 x.example\n", 1<<12)
			for n := 0; n <= FetchMaxBytes; n += len(chunk) {
				if _, err := fmt.Fprint(w, chunk); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPFetch(t *testing.T) {
	srv := listServer(t)
	body, err := HTTPFetch(srv.URL + "/moved")
	if err != nil || !strings.Contains(string(body), "ads.example") {
		t.Fatalf("a redirect: %q, %v", body, err)
	}
	for _, path := range []string{"/gone", "/huge"} {
		if _, err := HTTPFetch(srv.URL + path); !errors.Is(err, errFetch) {
			t.Errorf("%s: %v, want a failed download", path, err)
		}
	}
	if _, err := HTTPFetch("http://127.0.0.1:1/x"); !errors.Is(err, errFetch) {
		t.Errorf("nothing listening: %v, want a failed download", err)
	}
}

// TestRefreshAdblock refreshes from a real HTTP server: the lists are
// written, a stale category goes, and a source that fails is reported.
func TestRefreshAdblock(t *testing.T) {
	srv := listServer(t)
	raw, err := config.LoadYAML(fmt.Sprintf(`version: 1
hostname: r
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.7.1/24}
zones: {wan: {}, lan: {}}
adblocker:
  enabled: true
  source_urls: ["%[1]s/hosts", "%[1]s/gone"]
  categories: {malware: ["%[1]s/malware"]}
  allowlist: [good.example]
`, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	sys := DefaultSystem()
	sys.Paths = DefaultPaths().Under(root)
	sys.Euid = func() int { return 0 }
	stale := categoryPath(sys.Paths.AdblockCategoryDir, "old")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("0.0.0.0 old.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := sys.RefreshAdblock(c)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("3 deduped domains written (ads=2, malware=1) (1 source(s) failed: ['%s/gone'])", srv.URL)
	if r.Message != want || r.DomainCount != 3 {
		t.Errorf("got %+v\nwant %q", r, want)
	}
	for path, text := range map[string]string{
		sys.Paths.AdblockHosts:                                hostsFileHeader + "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n",
		categoryPath(sys.Paths.AdblockCategoryDir, "malware"): hostsFileHeader + "0.0.0.0 evil.example\n",
	} {
		if got, err := os.ReadFile(path); err != nil || string(got) != text {
			t.Errorf("%s: %q, %v", path, got, err)
		}
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stale category is still there: %v", err)
	}

	sys.Euid = func() int { return 1000 }
	if _, err := sys.RefreshAdblock(c); err == nil || err.Error() != "Refreshing the ad-block list requires root privileges." {
		t.Errorf("not root: %v", err)
	}
}
