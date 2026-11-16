package helper

import (
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/version"
)

// firewall-cli update (1.x's frfw.cli update commands): check for a newer
// release, the periodic check fr-update-check.timer runs (G10, and with
// update.auto_install_security the install of a security release, J3),
// and installing or rolling back a release as root from the console.

// timerAlert is who the periodic check's alerts are from (_TIMER).
const (
	timerUser   = "fr-update-check"
	timerClient = "timer"
)

func (c *cli) installed() string {
	if c.s.Env.Installed != "" {
		return c.s.Env.Installed
	}
	return version.Version
}

func (c *cli) fetch() apply.FetchJSON {
	if c.s.Env.Fetch != nil {
		return c.s.Env.Fetch
	}
	return apply.FetchGitHub
}

func (c *cli) updater(repo string) *apply.Updater {
	if c.s.Env.Updater != nil {
		return c.s.Env.Updater(repo)
	}
	u := apply.NewUpdater(c.s.sys(), repo)
	u.Installed = c.installed()
	return u
}

// updateRepo is _resolve_update_repo: the config's update.repo, or the
// default when it is unset or the config can't be read -- checking for
// updates shouldn't need a perfectly valid config.
func updateRepo(path string) string {
	cfg, _, err := apply.ReadConfig(path)
	if err != nil || cfg.Update.Repo == "" {
		return apply.DefaultUpdateRepo
	}
	return cfg.Update.Repo
}

// autoInstallSecurity is _auto_install_security: never install on a
// guess.
func autoInstallSecurity(path string) bool {
	cfg, _, err := apply.ReadConfig(path)
	return err == nil && cfg.Update.AutoInstallSecurity
}

// withCodenameASCII is the CLI's _with_codename: the codename in plain
// double quotes.
func withCodenameASCII(v string) string {
	if name := version.Codename(v); name != "" {
		return v + ` "` + name + `"`
	}
	return v
}

func (c *cli) update(a *cliArgs) (int, bool, error) {
	if !strings.HasPrefix(a.command, "update ") {
		return 0, false, nil
	}
	sys := c.s.sys()
	switch a.command {
	case "update check":
		repo := updateRepo(a.config)
		r, err := apply.CheckLatest(c.fetch(), sys.Now(), c.installed(), repo)
		if err != nil {
			return 0, true, err
		}
		c.println("Installed version: " + withCodenameASCII(r.Current))
		c.println("Repo checked:      " + repo)
		if r.Latest == nil {
			c.println("No releases published for this repo yet.")
			return 0, true, nil
		}
		c.println("Latest release:    " + withCodenameASCII(r.Latest.Version) + " (" + r.Latest.Tag + ")")
		if r.UpdateAvailable {
			c.println("Update available.")
			if r.Latest.Notes != "" {
				c.println("\nRelease notes:")
				c.println(r.Latest.Notes)
			}
		} else {
			c.println("Already up to date.")
		}
		return 0, true, nil
	case "update auto":
		return c.updateAuto(a.config)
	case "update apply":
		installed, err := c.updater(a.values["--repo"]).Apply(a.positional["version"])
		if err != nil {
			return 0, true, err
		}
		c.println("Updated to " + installed)
		return 0, true, nil
	case "update rollback":
		restored, err := c.updater(a.values["--repo"]).Rollback()
		if err != nil {
			return 0, true, err
		}
		c.println("Rolled back to " + restored)
		return 0, true, nil
	}
	return 0, false, nil
}

// updateAuto is _cmd_update_auto, fr-update-check.timer's job. G10: check
// once and record what was found for the webUI's banner (red for a
// security release); a failed check keeps what the last good one found,
// with the error. J3: with update.auto_install_security, also install a
// security release -- verified first, as every update -- and tell the
// admins either way.
func (c *cli) updateAuto(path string) (int, bool, error) {
	sys := c.s.sys()
	current := c.installed()
	repo := updateRepo(path)
	r, err := apply.CheckLatest(c.fetch(), sys.Now(), current, repo)
	if err != nil {
		data := apply.ReadCheckCache(sys.Paths.UpdateCheck, current)
		if data == nil {
			data = config.NewMap()
		}
		data.Set("current_version", current)
		data.Set("error", err.Error())
		if werr := apply.WriteCheckCache(sys.Paths.UpdateCheck, data); werr != nil {
			return 0, true, werr
		}
		c.eprintln("update check failed: " + err.Error())
		return 1, true, nil
	}
	if err := apply.WriteCheckCache(sys.Paths.UpdateCheck, apply.CheckCache(r, nil, nil)); err != nil {
		return 0, true, err
	}
	if r.Latest == nil || !r.UpdateAvailable {
		c.println("FR_OS " + current + " is up to date")
		return 0, true, nil
	}
	v := r.Latest.Version
	if !r.Latest.Security {
		c.println("update available: " + v)
		return 0, true, nil
	}
	c.println("SECURITY update available: " + v)
	if !autoInstallSecurity(path) {
		return 0, true, nil
	}
	installed, err := c.updater(repo).Apply(v)
	if err != nil {
		if werr := apply.WriteCheckCache(sys.Paths.UpdateCheck, apply.CheckCache(r, nil, err.Error())); werr != nil {
			return 0, true, werr
		}
		sys.Alert("automatic install of security release "+v+" failed: "+err.Error(), timerUser, timerClient)
		c.eprintln("automatic install of " + v + " failed: " + err.Error())
		return 1, true, nil
	}
	// The software changed without anyone clicking: that is an alert (G9).
	sys.Alert("security release "+installed+" installed automatically (was "+current+")", timerUser, timerClient)
	c.println("installed security release " + installed)
	return 0, true, nil
}
