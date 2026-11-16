package helper

import (
	"bufio"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
)

// The update-helper answers root and the webUI's account only: a sensor
// daemon, or anyone else who reaches the socket, is refused before the
// request is looked at (1.x's update_server, FULL role only).
func TestUpdateHelperAnswersFullPeersOnly(t *testing.T) {
	sys := apply.DefaultSystem()
	sys.Paths = apply.DefaultPaths().Under(t.TempDir())
	u := &UpdateServer{Sys: sys, Policy: func() Policy {
		return Policy{FullUIDs: map[int]bool{0: true, 990: true}, SensorUIDs: map[int]bool{991: true}}
	}}
	ask := func(uid int, line string) string {
		t.Helper()
		reply, err := u.Answer(bufio.NewReader(strings.NewReader(line+"\n")), 1, uid)
		if err != nil {
			return "no reply"
		}
		b, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for uid, want := range map[int]string{
		0:    `{"ok":true,"message":"pong"}`,
		990:  `{"ok":true,"message":"pong"}`,
		991:  `{"ok":false,"message":"uid 991 may not use the update-helper"}`,
		1000: `{"ok":false,"message":"uid 1000 may not use the update-helper"}`,
	} {
		if got := ask(uid, `{"cmd": "ping"}`); got != want {
			t.Errorf("uid %d: %s, want %s", uid, got, want)
		}
	}
	// A development build installs no release: its version isn't one
	// (fails closed); and nothing was installed to roll back from. The
	// rest of apply and rollback is apply.Updater's (its tests, the 1.x
	// replay of the update cases).
	for line, want := range map[string]string{
		`{"cmd": "apply", "version": "2.0.0"}`: `{"ok":false,"message":"not a recognized vMAJOR.MINOR.PATCH version: '0.0.0-dev'"}`,
		`{"cmd": "apply", "version": ""}`:      `{"ok":false,"message":"'version' must be a non-empty string"}`,
		`{"cmd": "apply", "version": 2}`:       `{"ok":false,"message":"'version' must be a non-empty string"}`,
		`{"cmd": "apply"}`:                     `{"ok":false,"message":"'version' must be a non-empty string"}`,
		`{"cmd": "rollback"}`:                  `{"ok":false,"message":"no previous version recorded to roll back to"}`,
	} {
		if got := ask(0, line); got != want {
			t.Errorf("%s: %s, want %s", line, got, want)
		}
	}
	if got := ask(0, `[1]`); got != `{"ok":false,"message":"invalid request: request must be a JSON object"}` {
		t.Errorf("not an object: %s", got)
	}
}
