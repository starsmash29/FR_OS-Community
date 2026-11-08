package ipc

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
)

type vector struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
	Max  int    `json:"max"`
	Want string `json:"want"`
}

var kinds = map[error]string{
	ErrEOF: "eof", ErrTruncated: "truncated", ErrTooLong: "too_long", ErrInvalidUTF8: "invalid_utf8",
	ErrInvalidJSON: "invalid_json", ErrNotObject: "not_object", ErrDuplicate: "duplicate_key",
}

func kind(err error) string {
	if err == nil {
		return "ok"
	}
	for e, k := range kinds {
		if errors.Is(err, e) {
			return k
		}
	}
	return "other: " + err.Error()
}

// The shared vectors: the Rust side runs the same file.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/ipc/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 20 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		data, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		var msg map[string]any
		got := kind(Read(bufio.NewReaderSize(bytes.NewReader(data), 16), v.Max, &msg))
		if got != v.Want {
			t.Errorf("%s: got %s, want %s", v.Name, got, v.Want)
		}
	}
}

// A line far past the limit is refused without reading all of it.
func TestTooLongStopsReading(t *testing.T) {
	src := strings.NewReader(strings.Repeat("x", 1<<20) + "\n")
	r := bufio.NewReaderSize(src, 4096)
	if _, err := ReadLine(r, 1024); !errors.Is(err, ErrTooLong) {
		t.Fatalf("got %v", err)
	}
	if read := (1 << 20) + 1 - src.Len(); read > 8192 {
		t.Fatalf("read %d bytes for a 1024-byte limit", read)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := map[string]any{"cmd": "apply", "args": map[string]any{"confirm": true}}
	if err := Write(&buf, MaxLineBytes, in); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := Read(bufio.NewReader(&buf), MaxLineBytes, &out); err != nil {
		t.Fatal(err)
	}
	if out["cmd"] != "apply" {
		t.Fatalf("got %v", out)
	}
}

func TestWriteRefusesNonObjectsAndLongLines(t *testing.T) {
	if err := Write(&bytes.Buffer{}, MaxLineBytes, []int{1}); !errors.Is(err, ErrNotObject) {
		t.Fatalf("array: %v", err)
	}
	if err := Write(&bytes.Buffer{}, 8, map[string]string{"k": "long value"}); !errors.Is(err, ErrTooLong) {
		t.Fatalf("long: %v", err)
	}
}
