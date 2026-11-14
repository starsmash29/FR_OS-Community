package apply

import (
	"errors"
	"strings"
	"testing"
)

// TestReadAnswer is getpass's reading of the answer: one line without
// its newline, a last line with none, and no line at all as the end of
// input (Python's EOFError), so set-admin-password stops there.
func TestReadAnswer(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"secret\nmore\n", "secret"},
		{"no newline", "no newline"},
		{"\n", ""},
		{"crlf\r\n", "crlf\r"}, // the terminal's line, as Python keeps it
	} {
		got, err := readAnswer(strings.NewReader(c.in))
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := readAnswer(strings.NewReader("")); !errors.Is(err, ErrNoInput) {
		t.Errorf("empty input: %v, want ErrNoInput", err)
	}
}
