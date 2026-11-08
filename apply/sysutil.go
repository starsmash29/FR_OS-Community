package apply

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/starsmash29/fr_os-community/config"
)

// Python's pathlib, as the steps use it.

// readText is Path.read_text(): ok false when it can't be read.
func readText(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// exists is Path.exists().
func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// isDir is Path.is_dir().
func isDir(path string) bool { st, err := os.Stat(path); return err == nil && st.IsDir() }

// isFile is Path.is_file().
func isFile(path string) bool { st, err := os.Stat(path); return err == nil && st.Mode().IsRegular() }

// writeText is Path.write_text(): the file truncated in place, created
// 0666 less the umask when it is new.
func writeText(path, text string) error {
	return os.WriteFile(path, []byte(text), 0o666)
}

// mkdirParent is path.parent.mkdir(parents=True, exist_ok=True).
func mkdirParent(path string) error { return os.MkdirAll(filepath.Dir(path), 0o777) }

// unlinkMissingOK is Path.unlink(missing_ok=True).
func unlinkMissingOK(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// replaceFile writes text to a temporary name next to path (tmpName),
// with mode, then renames it over path: a reader sees the old file or
// the new one, never half of it.
func replaceFile(path, tmpName, text string, mode fs.FileMode) error {
	if err := mkdirParent(path); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), tmpName)
	if err := os.WriteFile(tmp, []byte(text), 0o666); err != nil {
		return err
	}
	if mode != 0 {
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

// osErrorText is str(OSError) for the errors the steps report:
// "[Errno 13] Permission denied: '/path'".
func osErrorText(err error) string {
	var pe *fs.PathError
	var no syscall.Errno
	if errors.As(err, &pe) && errors.As(pe.Err, &no) {
		text := no.Error()
		if text != "" {
			text = strings.ToUpper(text[:1]) + text[1:]
		}
		return "[Errno " + strconv.Itoa(int(no)) + "] " + text + ": " + config.Repr(pe.Path)
	}
	return err.Error()
}

// parseGroupMembers is gr_mem of group name in an /etc/group text.
func parseGroupMembers(text, name string) ([]string, error) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] != name {
			continue
		}
		if fields[3] == "" {
			return nil, nil
		}
		return strings.Split(fields[3], ","), nil
	}
	return nil, errNoGroup
}

var opensslVersionRE = regexp.MustCompile(`\AOpenSSL (\d+)\.(\d+)\.(\d+)`)

// hostOpenSSL is the host OpenSSL's version (`openssl version`), or
// zeros when it can't be told: no hybrid TLS then.
func hostOpenSSL() ([3]int, string) {
	res, err := Run(Cmd{Argv: []string{"openssl", "version"}})
	if err != nil || res.Code != 0 {
		return [3]int{}, "unknown"
	}
	return parseOpenSSLVersion(res.Stdout)
}

// parseOpenSSLVersion reads `openssl version`: the library's version
// (what Python's ssl module reports), which the program prints after
// its own, as "(Library: ...)", when the two differ.
func parseOpenSSLVersion(out string) ([3]int, string) {
	text := strings.TrimSpace(out)
	if _, lib, ok := strings.Cut(text, "(Library: "); ok && strings.HasSuffix(lib, ")") {
		text = strings.TrimSuffix(lib, ")")
	}
	m := opensslVersionRE.FindStringSubmatch(text)
	if m == nil {
		return [3]int{}, text
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, text
}
