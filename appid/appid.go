// Package appid is the application catalog: which domain names belong to
// which app (TikTok, WhatsApp, ...), for app control's blocklists.
//
// signatures.json is the same catalog 1.x ships (src/frfw/appid), built
// from v2fly/domain-list-community (MIT licence; its "source", "license"
// and "ref" fields say which commit).
package appid

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed signatures.json
var signaturesJSON []byte

// App is one catalog entry.
type App struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"` // the name and every subdomain
	Exact    []string `json:"exact"`   // only this precise name
}

// Catalog is the parsed signatures.json.
type Catalog struct {
	Source    string `json:"source"`
	License   string `json:"license"`
	Ref       string `json:"ref"`
	Generated string `json:"generated"`
	Apps      []App  `json:"apps"`
	byID      map[string]*App
}

var (
	once    sync.Once
	catalog *Catalog
	loadErr error
)

// Load is the bundled catalog, parsed once.
func Load() (*Catalog, error) {
	once.Do(func() { catalog, loadErr = parse(signaturesJSON) })
	return catalog, loadErr
}

func parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("appid: %w", err)
	}
	c.byID = map[string]*App{}
	for i := range c.Apps {
		app := &c.Apps[i]
		if _, dup := c.byID[app.ID]; dup {
			return nil, fmt.Errorf("appid: apps[%d]: duplicate app id %q", i, app.ID)
		}
		for j := range app.Domains {
			app.Domains[j] = strings.ToLower(app.Domains[j])
		}
		for j := range app.Exact {
			app.Exact[j] = strings.ToLower(app.Exact[j])
		}
		c.byID[app.ID] = app
	}
	return &c, nil
}

// Known reports whether id is an app of the catalog.
func (c *Catalog) Known(id string) bool { _, ok := c.byID[id]; return ok }

// BlockingNames is every catalog name of the given apps, sorted and
// without repeats: the resolver and the XDP filter block a name and its
// subdomains. Unknown ids are skipped (the config refuses them).
func (c *Catalog) BlockingNames(ids []string) []string {
	set := map[string]bool{}
	for _, id := range ids {
		if app := c.byID[id]; app != nil {
			for _, n := range app.Domains {
				set[n] = true
			}
			for _, n := range app.Exact {
				set[n] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
