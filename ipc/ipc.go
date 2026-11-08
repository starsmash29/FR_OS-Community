// Package ipc is the wire format between FR_OS processes on a Unix
// socket: one JSON object per line, both directions, as FR_OS 1.x's
// apply-helper speaks it (frfw.helper.protocol), so a 2.x helper can
// serve a 1.x webUI during the move and the other way round.
//
// A line is checked before anything acts on it: at most max bytes up to
// the newline (the reader never buffers more), UTF-8, valid JSON, an
// object at the top, and no name twice in any object (RFC 7493, I-JSON).
// The last two are what encoding/json/v2 enforces by default; a peer
// that sends {"cmd":"status","cmd":"apply"} must not have one side read
// "status" and the other "apply". The Rust side (crates/fros-ipc) makes
// the same calls on the same test vectors (testdata/ipc/vectors.json).
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxLineBytes is the default line limit, frfw.helper.protocol's
// MAX_LINE_BYTES. Replies that carry bulk data (a conntrack sample) are
// read with their own, larger limit.
const MaxLineBytes = 64 * 1024

// Why a line was refused. Each is wrapped in a *LineError.
var (
	ErrEOF         = errors.New("ipc: end of stream")
	ErrTruncated   = errors.New("ipc: stream ended inside a line")
	ErrTooLong     = errors.New("ipc: line too long")
	ErrInvalidUTF8 = errors.New("ipc: line is not UTF-8")
	ErrInvalidJSON = errors.New("ipc: line is not JSON")
	ErrNotObject   = errors.New("ipc: line is not a JSON object")
	ErrDuplicate   = errors.New("ipc: a name appears twice in an object")
)

// ReadLine reads one line (without its newline) of at most max bytes.
// Bytes past the limit are not read: after ErrTooLong the stream is out
// of step and the connection must be closed.
func ReadLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max+1 || (err == bufio.ErrBufferFull && len(line)+len(chunk) > max) {
			return nil, ErrTooLong
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF && len(line) == 0:
			return nil, ErrEOF
		case err == io.EOF:
			return nil, ErrTruncated
		default:
			return nil, err
		}
	}
}

// Check says whether line is one acceptable message, and why not.
func Check(line []byte) error {
	if !utf8.Valid(line) {
		return ErrInvalidUTF8
	}
	v := jsontext.Value(bytes.TrimSpace(line))
	if !v.IsValid(jsontext.AllowDuplicateNames(true)) {
		return ErrInvalidJSON
	}
	if v.Kind() != '{' {
		return ErrNotObject
	}
	if !v.IsValid() {
		return ErrDuplicate
	}
	return nil
}

// Read reads and checks one message and decodes it into out.
func Read(r *bufio.Reader, max int, out any) error {
	line, err := ReadLine(r, max)
	if err != nil {
		return err
	}
	if err := Check(line); err != nil {
		return err
	}
	if err := json.Unmarshal(line, out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return nil
}

// Write encodes msg as one line. It refuses anything that is not a JSON
// object or is longer than max, so a peer never has to.
func Write(w io.Writer, max int, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := Check(b); err != nil {
		return err
	}
	if len(b) > max {
		return ErrTooLong
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
