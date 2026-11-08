package apply

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// FileState is a file's bytes, mode and owner, or that it didn't exist
// (frfw.transaction.FileState): what a step that writes a file puts back.
type FileState struct {
	Path     string
	Content  []byte // nil: there was no file
	Mode     fs.FileMode
	UID, GID int
}

// CaptureFile reads path as it is now.
func CaptureFile(path string) (FileState, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{Path: path, Mode: 0o644}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{Path: path, Mode: 0o644}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	if content == nil {
		content = []byte{}
	}
	s := st.Sys().(*syscall.Stat_t)
	return FileState{path, content, permBits(st.Mode()), int(s.Uid), int(s.Gid)}, nil
}

// permBits are the mode's low twelve bits (`st_mode & 0o7777`).
func permBits(m fs.FileMode) fs.FileMode {
	out := m.Perm()
	if m&fs.ModeSetuid != 0 {
		out |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		out |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		out |= 0o1000
	}
	return out
}

func toFileMode(bits fs.FileMode) fs.FileMode {
	m := bits.Perm()
	if bits&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if bits&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if bits&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// Differs reports whether the file is no longer as captured.
func (f FileState) Differs() (bool, error) {
	now, err := CaptureFile(f.Path)
	if err != nil {
		return false, err
	}
	return !f.equal(now), nil
}

func (f FileState) equal(o FileState) bool {
	if (f.Content == nil) != (o.Content == nil) {
		return false
	}
	if f.Content == nil {
		return true
	}
	return bytes.Equal(f.Content, o.Content) && f.Mode == o.Mode && f.UID == o.UID && f.GID == o.GID
}

// Restore puts the file back: removed if there was none, else its bytes,
// mode and (as root) owner, written atomically.
func (f FileState) Restore() error {
	if f.Content == nil {
		if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), "."+filepath.Base(f.Path)+".")
	if err != nil {
		return err
	}
	name := tmp.Name()
	err = func() error {
		_, err := tmp.Write(f.Content)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Chmod(name, toFileMode(f.Mode))
		}
		if err == nil && os.Geteuid() == 0 {
			err = os.Chown(name, f.UID, f.GID)
		}
		if err == nil {
			err = os.Rename(name, f.Path)
		}
		return err
	}()
	if err != nil {
		os.Remove(name)
	}
	return err
}

// WritePrivate writes path atomically, root's alone (0600): the record
// of the applied config holds what config.yaml holds, ZTNA password
// hashes included.
func WritePrivate(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.WriteString(text)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// WebUIUser is the webUI's account; config.yaml is root:fr_os-webui 0640.
const WebUIUser = "fr_os-webui"

// WriteKeepingOwner replaces path atomically, keeping its owner and
// mode. config.yaml is root:fr_os-webui 0640 (it holds ZTNA password
// hashes and the metrics token's digest); a plain write and rename left
// it root:root 0644, world-readable, after the first save from the webUI.
// The temporary file is created 0600, so it is never briefly readable,
// then given the old file's owner and mode and renamed over it. A new
// file gets root:fr_os-webui 0640 (the caller's group when there is
// no such group).
func WriteKeepingOwner(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var uid, gid int
	var mode fs.FileMode
	if st, err := os.Stat(path); err == nil {
		s := st.Sys().(*syscall.Stat_t)
		uid, gid, mode = int(s.Uid), int(s.Gid), permBits(st.Mode())
	} else if errors.Is(err, fs.ErrNotExist) {
		uid, gid, mode = os.Geteuid(), os.Getegid(), 0o640
		if g, ok := groupOf(WebUIUser); ok {
			gid = g
		}
	} else {
		return err
	}
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && os.Geteuid() == 0 {
		err = os.Chown(tmp, uid, gid)
	}
	if err == nil {
		err = os.Chmod(tmp, toFileMode(mode))
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// groupOf is group name's id (frfw.helper.peer.gid_of).
func groupOf(name string) (int, bool) {
	g0, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	g, err := strconv.Atoi(g0.Gid)
	return g, err == nil
}
