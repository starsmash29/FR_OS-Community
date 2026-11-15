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
	// Signed releases are phase 4f-4's.
	for _, cmd := range []string{"apply", "rollback"} {
		want := `{"ok":false,"message":"unknown command '` + cmd + `'"}`
		if got := ask(0, `{"cmd": "`+cmd+`", "version": "2.0.0"}`); got != want {
			t.Errorf("%s: %s, want %s", cmd, got, want)
		}
	}
	if got := ask(0, `[1]`); got != `{"ok":false,"message":"invalid request: request must be a JSON object"}` {
		t.Errorf("not an object: %s", got)
	}
}
