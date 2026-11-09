package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// --- refreshing the ad-block lists (frfw.adblock.refresh) -------------------------
//
// The one thing an apply-helper command fetches from the internet: the
// blocklists the admin named in adblocker.source_urls and
// adblocker.categories, when the admin asks for a refresh (the webUI's
// "Refresh now", or the daily timer). Nothing is fetched while the
// ad-blocker isn't configured (G11: opt-in), and an apply never fetches.

// BaseCategory is the name the unnamed base list (adblocker.source_urls)
// goes by wherever per-category counts appear.
const BaseCategory = "ads"

// Limits of one download: 1.x has a 15 s timeout for each blocking
// socket operation and no size limit. FR_OS 2 keeps the 15 s for
// connecting, the TLS handshake and the response's headers, and adds a
// whole-download limit of time and size (AGENTS.md: every read from the
// network has a size limit; testdata/reference/decisions.md).
const (
	FetchTimeout      = 15 * time.Second
	FetchTotalTimeout = 120 * time.Second
	FetchMaxBytes     = 64 << 20
	fetchWorkers      = 4 // 1.x's DEFAULT_MAX_WORKERS
)

// errFetch: 1.x reports a failed download only by its URL (the
// AdblockError's text is never shown), so the reason is Go's words.
var errFetch = errors.New("could not fetch")

var fetchClient = &http.Client{
	Timeout: FetchTotalTimeout,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment, // urllib honours the *_proxy variables too
		DialContext:           (&net.Dialer{Timeout: FetchTimeout}).DialContext,
		TLSHandshakeTimeout:   FetchTimeout,
		ResponseHeaderTimeout: FetchTimeout,
		ForceAttemptHTTP2:     true,
	},
}

// HTTPFetch is frfw.adblock._fetch_url: GET url, as "fr_os-adblock", and
// the body.
func HTTPFetch(rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), FetchTotalTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errFetch, rawURL, err)
	}
	req.Header.Set("User-Agent", "fr_os-adblock")
	resp, err := fetchClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errFetch, rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 { // urllib's HTTPError, after redirects
		return nil, fmt.Errorf("%w %s: HTTP %s", errFetch, rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, FetchMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errFetch, rawURL, err)
	}
	if len(body) > FetchMaxBytes {
		return nil, fmt.Errorf("%w %s: larger than %d bytes", errFetch, rawURL, FetchMaxBytes)
	}
	return body, nil
}

// AdblockRefresh is what a refresh did: the domains written, per list
// (the base list first, then the categories by name), and the sources
// that failed.
type AdblockRefresh struct {
	DomainCount int
	FailedURLs  []string
	Message     string
	Counts      []NameCount
}

// NameCount is one list's domains.
type NameCount struct {
	Name  string
	Count int
}

// fetchAndParse downloads every URL of one list, at most fetchWorkers at
// once, and unites their domains. It fails only when every URL failed:
// an empty result would blank the list. failed is in the order the URLs
// are listed (1.x's is the order the downloads ended in).
func (s *System) fetchAndParse(urls []string) (domains map[string]bool, failed []string, err error) {
	texts := make([][]byte, len(urls))
	errs := make([]error, len(urls))
	var wg sync.WaitGroup
	slots := make(chan struct{}, fetchWorkers)
	for i, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			texts[i], errs[i] = s.Fetch(u)
		}()
	}
	wg.Wait()
	domains = map[string]bool{}
	for i, u := range urls {
		if errs[i] != nil {
			failed = append(failed, u)
			continue
		}
		// .decode("utf-8", errors="replace"): what is replaced is never
		// part of a name, so it doesn't matter how many U+FFFD stand
		// for it.
		for d := range parseHostsText(strings.ToValidUTF8(string(texts[i]), "\ufffd")) {
			domains[d] = true
		}
	}
	if len(failed) > 0 && len(failed) == len(urls) {
		return nil, failed, fmt.Errorf("all %d source_urls failed to fetch: %s", len(urls), strListRepr(failed))
	}
	return domains, failed, nil
}

func strListRepr(list []string) string {
	values := make([]config.Value, len(list))
	for i, s := range list {
		values[i] = s
	}
	return config.Repr(values)
}

// RefreshAdblock is frfw.adblock.refresh as the apply-helper calls it:
// fetch every list, drop the names never blocked (the allowlist, the
// local names, Firefox's DoH canary), and write the base list and one
// file per category. A list whose every source is down keeps its
// previous file; category files no longer in the config are removed.
func (s *System) RefreshAdblock(c *config.Config) (*AdblockRefresh, error) {
	sources := c.Adblocker.SourceURLs
	categories := &c.Adblocker.Categories
	if len(sources) == 0 && categories.Len() == 0 {
		return nil, stepErr("adblocker.source_urls and adblocker.categories are both empty; nothing to fetch")
	}
	type list struct {
		name string
		urls []string
		path string
	}
	var lists []list
	if len(sources) > 0 {
		lists = append(lists, list{BaseCategory, sources, s.Paths.AdblockHosts})
	}
	for _, name := range slices.Sorted(slices.Values(categories.Keys)) {
		urls, _ := categories.Get(name)
		lists = append(lists, list{name, urls, categoryPath(s.Paths.AdblockCategoryDir, name)})
	}
	allow := append(neverBlocked(c), render.FirefoxDoHCanary)
	fetched := map[string]map[string]bool{}
	var counts []NameCount
	var failedURLs, problems []string
	for _, l := range lists {
		domains, failed, err := s.fetchAndParse(l.urls)
		if err != nil {
			problems = append(problems, l.name+": "+err.Error())
			failedURLs = append(failedURLs, l.urls...)
			continue
		}
		kept := map[string]bool{}
		for d := range domains {
			if !allowlisted(d, allow) {
				kept[d] = true
			}
		}
		fetched[l.name] = kept
		counts = append(counts, NameCount{l.name, len(kept)})
		failedURLs = append(failedURLs, failed...)
	}
	if len(fetched) == 0 {
		return nil, stepErr("%s", strings.Join(problems, "; "))
	}
	total := 0
	var summary []string
	for _, n := range counts {
		total += n.Count
		summary = append(summary, fmt.Sprintf("%s=%d", n.Name, n.Count))
	}
	if !s.root() {
		return nil, stepErr("Refreshing the ad-block list requires root privileges.")
	}
	for _, l := range lists {
		if kept, ok := fetched[l.name]; ok {
			if err := writeHostsFile(kept, l.path); err != nil {
				return nil, err
			}
		}
	}
	if len(sources) == 0 {
		// The base list was taken out of the config: stop blocking it.
		if err := writeHostsFile(map[string]bool{}, s.Paths.AdblockHosts); err != nil {
			return nil, err
		}
	}
	if err := removeStaleCategories(s.Paths.AdblockCategoryDir, categories); err != nil {
		return nil, err
	}
	message := fmt.Sprintf("%d deduped domains written (%s)", total, strings.Join(summary, ", "))
	if len(problems) > 0 {
		message += "; kept previous list for: " + strings.Join(problems, "; ")
	} else if len(failedURLs) > 0 {
		message += fmt.Sprintf(" (%d source(s) failed: %s)", len(failedURLs), strListRepr(failedURLs))
	}
	if failedURLs == nil {
		failedURLs = []string{}
	}
	return &AdblockRefresh{DomainCount: total, FailedURLs: failedURLs, Message: message, Counts: counts}, nil
}

// removeStaleCategories removes every "*.hosts" in dir whose stem isn't
// a category: dropping a category unblocks it.
func removeStaleCategories(dir string, categories *config.Ordered[[]string]) error {
	if !isDir(dir) {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return pyOSError(err)
	}
	for _, e := range entries {
		name := e.Name()
		stem, ok := strings.CutSuffix(name, ".hosts")
		if !ok {
			continue
		}
		if stem == "" { // Path(".hosts").stem is ".hosts"
			stem = name
		}
		if categories.Has(stem) {
			continue
		}
		path := filepath.Join(dir, name)
		if err := syscall.Unlink(path); err != nil { // Path.unlink(): never a directory
			return pyOSError(&os.PathError{Op: "unlink", Path: path, Err: err})
		}
	}
	return nil
}
