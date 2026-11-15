package apply

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// Debian's kernel fixes, prepared for a trial boot (ROADMAP SEC-14, step
// 3; 1.x's frfw.kernel_update).
//
// The staged-kernel machinery (kernelboot.go) tries a kernel once and
// keeps it only when the router comes up on it. This gets the kernel to
// stage: once a day (fr-kernel-prepare.timer, update.kernel_updates, on
// by default) it asks apt which kernel Debian's linux-image-amd64 points
// at now and, if that is a newer ABI than every kernel the router has,
// installs it -- from the configured Debian archive, its Release
// signatures checked by apt against debian-archive-keyring, the same
// chain as every other package (the one install from the network FR_OS
// makes by itself, and only with update.kernel_updates on).
//
// Installed into the live system's persistent root, the package puts
// /boot/vmlinuz-<v> and its modules (/usr/lib/modules/<v>) on the
// persistence partition. Its initrd is not built with mkinitramfs on the
// router: one made inside the running live system lacked libmount and
// the kernel panicked (found by 1.x's boot test). It is the image's own
// initrd, the one the medium boots with, with its kernel modules
// exchanged for the new kernel's: the same modules plus what they depend
// on, depmod run for the new kernel. Nothing else in an initrd (busybox,
// live-boot, the libraries) depends on the kernel version. The archive
// is edited, not unpacked -- every other entry is copied byte for byte,
// setuid mount and device nodes included -- and checked for live-boot
// and the new kernel's modules before the kernel is called ready.
//
// It never stages and never reboots: the kernel is "ready to try". The
// admin's "Try it" on the Update screen (the update-helper's kernel_try)
// stages it and reboots into its trial -- the only reboot FR_OS asks
// for. So a power cut boots the known kernel, not an untried one.
//
// unattended-upgrades keeps excluding the kernel (hooks/0050): only this
// path installs one, and it removes again what it installed once a
// kernel is neither prepared, staged, running nor the image's own. The
// image's kernel package is never touched: its modules are what the
// fallback boots with.

const (
	kernelMetaPackage   = "linux-image-amd64"
	kernelPackagePrefix = "linux-image-"
	// What must stay free on the persistence partition after a kernel is
	// installed, and what its initrd and staged copy take besides (review
	// v0.2.1 #1): a full partition would stop config saves and logging.
	kernelReserveBytes = 256 << 20
	kernelExtraBytes   = 160 << 20
	kernelRunTimeout   = 1800 * time.Second
	// maxInitrdBytes bounds an initrd read or decompressed: Debian's,
	// with every module live-boot takes, is a small fraction of it.
	maxInitrdBytes = 1 << 30
)

// moduleIndex is what depmod needs next to the modules.
var moduleIndex = []string{"modules.order", "modules.builtin", "modules.builtin.modinfo"}

var (
	moduleSuffix = regexp.MustCompile(`\.ko(\.(xz|zst|gz))?\z`)
	kernelABI    = regexp.MustCompile(`\A(\d+)\.(\d+)\.(\d+)-(\d+)-amd64\z`)
	// candidateName is re.findall(r"linux-image-(\S+?)(?:\s|,|$)").
	candidateName = regexp.MustCompile(`linux-image-(\S+?)(?:\s|,|$)`)
)

// KernelUpdateError is a kernel that could not be prepared or tried;
// what the message says was left.
type KernelUpdateError struct{ msg string }

func (e *KernelUpdateError) Error() string { return e.msg }

func updateErr(format string, a ...any) error { return &KernelUpdateError{fmt.Sprintf(format, a...)} }

// RaisedError is an exception 1.x lets through where the commands catch
// only their own and OSError (a ValueError from a torn archive, apt's
// timeout): the CLI fails, the update-helper sends no reply.
type RaisedError struct{ Kind, Msg string }

func (e *RaisedError) Error() string { return e.Kind + ": " + e.Msg }

// kernelRun is 1.x's _run: apt and dpkg non-interactive, half an hour at
// most, a failure worded with the end of what it printed.
func (s *System) kernelRun(argv ...string) (string, error) {
	r, err := s.Run(Cmd{Argv: argv, Env: []string{"DEBIAN_FRONTEND=noninteractive"}, Timeout: kernelRunTimeout})
	switch {
	case errors.Is(err, ErrNotFound):
		return "", &fs.PathError{Op: "exec", Path: argv[0], Err: fs.ErrNotExist}
	case errors.Is(err, ErrTimeout):
		return "", &RaisedError{"TimeoutExpired", err.Error()}
	case err != nil:
		return "", err
	}
	if r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		out = config.PyStrip(out)
		if runes := []rune(out); len(runes) > 500 {
			out = string(runes[len(runes)-500:])
		}
		return "", updateErr("%s failed: %s", strings.Join(argv, " "), out)
	}
	return r.Stdout, nil
}

// kernelErrText is str(exc) of what the commands catch: an OSError as
// Python words it, a missing program as subprocess's FileNotFoundError.
func kernelErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Op == "exec" {
		return "[Errno 2] No such file or directory: " + config.Repr(pe.Path)
	}
	return osErrorText(err)
}

// KernelCaught is whether the kernel commands report err (1.x's except
// KernelUpdateError, KernelBootError, OSError) rather than let it
// through.
func KernelCaught(err error) bool {
	var re *RaisedError
	return !errors.As(err, &re)
}

// KernelErrorText is err as the kernel commands print it.
func KernelErrorText(err error) string { return kernelErrText(err) }

// abiKey is 6.1.0-54-amd64 as (6, 1, 0, 54); nil for anything else.
func abiKey(version string) []int {
	m := kernelABI.FindStringSubmatch(version)
	if m == nil {
		return nil
	}
	key := make([]int, 4)
	for i := range key {
		key[i], _ = strconv.Atoi(m[i+1])
	}
	return key
}

func newerKernel(version, than string) bool {
	mine, theirs := abiKey(version), abiKey(than)
	return mine != nil && (theirs == nil || slices.Compare(mine, theirs) > 0)
}

// kernelCandidate is the kernel ABI Debian's linux-image-amd64 points at
// now (apt's candidate), "" for none.
func (s *System) kernelCandidate() (string, error) {
	record, err := s.kernelRun("apt-cache", "show", "--no-all-versions", "--", kernelMetaPackage)
	if err != nil {
		return "", err
	}
	for _, line := range config.PySplitlines(record) {
		if !strings.HasPrefix(line, "Depends:") && !strings.HasPrefix(line, "Pre-Depends:") {
			continue
		}
		for _, m := range candidateName.FindAllStringSubmatch(line, -1) {
			if abiKey(m[1]) != nil {
				return m[1], nil
			}
		}
	}
	return "", nil
}

// --- what it remembers --------------------------------------------------------------

// kernelState is the state file's object, as json.load read it.
type kernelState struct{ m *config.Map }

func (s *System) loadKernelState() kernelState {
	empty := func() kernelState {
		m := config.NewMap()
		m.Set("installed", []config.Value{})
		return kernelState{m}
	}
	data, err := os.ReadFile(s.Paths.KernelUpdateState)
	if err != nil {
		return empty()
	}
	v, err := config.ParseJSONLastWins(data)
	m, ok := v.(*config.Map)
	if err != nil || !ok {
		return empty()
	}
	if !m.Has("installed") {
		m.Set("installed", []config.Value{})
	}
	return kernelState{m}
}

func (st kernelState) installed() []string {
	v, _ := st.m.Get("installed")
	list, _ := v.([]config.Value)
	var out []string
	for _, p := range list {
		if s, ok := p.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (st kernelState) setInstalled(packages []string) {
	list := make([]config.Value, len(packages))
	for i, p := range packages {
		list[i] = p
	}
	st.m.Set("installed", list)
}

// prepared is state["prepared"] or {}.
func (st kernelState) prepared() *config.Map {
	v, _ := st.m.Get("prepared")
	if m, ok := v.(*config.Map); ok {
		return m
	}
	return config.NewMap()
}

func mapString(m *config.Map, key string) string {
	v, _ := m.Get(key)
	s, _ := v.(string)
	return s
}

// saveKernelState writes the state file as json.dump(indent=2,
// sort_keys=True), 0600, through a temporary file.
func (s *System) saveKernelState(st kernelState) error {
	path := s.Paths.KernelUpdateState
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	text, err := config.PyJSON(st.m, 2, true)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *System) kernelNow() string {
	return s.Now().UTC().Format("2006-01-02T15:04:05") + "+00:00"
}

// --- preparing ----------------------------------------------------------------------

// imageKernels are the kernels whose modules are in the image itself
// (the squashfs).
func (s *System) imageKernels() map[string]bool {
	found := map[string]bool{}
	matches, _ := filepath.Glob(filepath.Join(globEscape(s.Paths.ImageRoot), "*", "usr", "lib", "modules", "*"))
	for _, m := range matches {
		if abiKey(filepath.Base(m)) != nil {
			found[filepath.Base(m)] = true
		}
	}
	return found
}

func (s *System) packageInstalled(pkg string) (bool, error) {
	out, err := s.kernelRun("dpkg-query", "-W", "-f=${Status}", "--", pkg)
	var ue *KernelUpdateError
	if errors.As(err, &ue) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return config.PyStrip(out) == "install ok installed", nil
}

// installedSize is the bytes the package takes once installed (apt's
// Installed-Size, KiB).
func (s *System) installedSize(pkg string) (uint64, error) {
	out, err := s.kernelRun("apt-cache", "show", "--no-all-versions", "--", pkg)
	if err != nil {
		return 0, err
	}
	for _, line := range config.PySplitlines(out) {
		if rest, ok := strings.CutPrefix(line, "Installed-Size:"); ok {
			n, err := strconv.ParseUint(config.PyStrip(rest), 10, 64)
			if err != nil {
				return 0, &RaisedError{"ValueError", "invalid literal for int() with base 10: " + config.Repr(config.PyStrip(rest))}
			}
			return n * 1024, nil
		}
	}
	return 0, updateErr("apt gives no installed size for %s", pkg)
}

// checkKernelRoom refuses an install that would leave the persistence
// partition with less than the reserve (review v0.2.1 #1).
func (s *System) checkKernelRoom(pkg, where string) error {
	size, err := s.installedSize(pkg)
	if err != nil {
		return err
	}
	needed := size + kernelExtraBytes + kernelReserveBytes
	free, err := s.DiskFree(where)
	if err != nil {
		return err
	}
	if free < needed {
		return updateErr("not enough room for %s: %d MiB free on the persistence partition, %d MiB needed (the "+
			"kernel, its initrd and a reserve) -- use a bigger stick, or turn kernel updates off", pkg, free>>20,
			needed>>20)
	}
	return nil
}

// KernelOutcome is what PrepareKernel did: its message, and the alert to
// raise (none when nothing changed).
type KernelOutcome struct{ Message, Alert string }

func stagedLive(state string) bool {
	return state == KernelTrial || state == KernelTrying || state == KernelGood || state == KernelBooting
}

// PrepareKernel gets the kernel to try ready. version: that one (an
// admin's choice; also how the boot test prepares a kernel without the
// network), "" for Debian's newest when it is newer than everything
// here; enabled is update.kernel_updates. bootDir is KernelBootDir's.
func (s *System) PrepareKernel(version string, given, enabled bool, bootDir string) (KernelOutcome, error) {
	running := s.KernelRelease()
	image := s.imageKernels()
	state := s.loadKernelState()
	staged := s.KernelStatus(true)
	failed := ""
	if staged.State == KernelFailed {
		failed = staged.Staged
	}

	if !given {
		if !enabled {
			return KernelOutcome{Message: "kernel updates are off (update.kernel_updates)"}, nil
		}
		if _, err := s.kernelRun("apt-get", "update", "-q"); err != nil {
			return KernelOutcome{}, err
		}
		v, err := s.kernelCandidate()
		if err != nil {
			return KernelOutcome{}, err
		}
		if v == "" {
			return KernelOutcome{}, updateErr("apt names no kernel for %s", kernelMetaPackage)
		}
		version = v
		have := []string{running, mapString(state.prepared(), "version")}
		if stagedLive(staged.State) {
			have = append(have, staged.Staged)
		}
		newest := ""
		for _, h := range have {
			if abiKey(h) != nil && (newest == "" || slices.Compare(abiKey(h), abiKey(newest)) > 0) {
				newest = h
			}
		}
		if !newerKernel(version, newest) {
			shown := newest
			if shown == "" {
				shown = "None"
			}
			return KernelOutcome{Message: fmt.Sprintf("no newer kernel: Debian's is %s, this router has %s", version,
				shown)}, nil
		}
		if version == failed {
			return KernelOutcome{Message: fmt.Sprintf("kernel %s failed its trial boot here; it is not prepared again",
				version)}, nil
		}
	}
	if err := checkKernelVersion(version); err != nil {
		return KernelOutcome{}, err
	}

	pkg := kernelPackagePrefix + version
	installed, err := s.packageInstalled(pkg)
	if err != nil {
		return KernelOutcome{}, err
	}
	if !installed {
		if err := s.checkKernelRoom(pkg, filepath.Dir(bootDir)); err != nil {
			return KernelOutcome{}, err
		}
		if _, err := s.kernelRun("apt-get", "install", "-y", "-q", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confold", "--", pkg); err != nil {
			return KernelOutcome{}, err
		}
		if list := state.installed(); !slices.Contains(list, pkg) {
			state.setInstalled(append(list, pkg))
			if err := s.saveKernelState(state); err != nil {
				return KernelOutcome{}, err
			}
		}
	}

	kernel := filepath.Join(s.Paths.Boot, "vmlinuz-"+version)
	if !isFile(kernel) && image[version] && isFile(s.Paths.MediumKernel) {
		kernel = s.Paths.MediumKernel // the image's own, as the medium boots it
	}
	if !isFile(kernel) {
		return KernelOutcome{}, updateErr("%s is installed but %s is not there", pkg, kernel)
	}
	initrd := filepath.Join(s.Paths.KernelInitrds, "initrd.img-"+version)
	if err := s.buildInitrd(s.Paths.MediumInitrd, filepath.Join(s.Paths.ModulesRoot, version), version,
		initrd); err != nil {
		return KernelOutcome{}, err
	}

	prepared := config.NewMap()
	prepared.Set("version", version)
	prepared.Set("kernel", kernel)
	prepared.Set("initrd", initrd)
	prepared.Set("prepared_at", s.kernelNow())
	state.m.Set("prepared", prepared)
	if err := s.saveKernelState(state); err != nil {
		return KernelOutcome{}, err
	}
	keep := map[string]bool{version: true, running: true}
	for k := range image {
		keep[k] = true
	}
	if staged.Staged != "" && staged.State != KernelFailed {
		keep[staged.Staged] = true
	}
	removed, err := s.cleanUpKernels(state, keep)
	if err != nil {
		return KernelOutcome{}, err
	}
	note := ""
	if len(removed) > 0 {
		note = "; removed " + strings.Join(removed, ", ")
	}
	return KernelOutcome{
		Message: fmt.Sprintf("kernel %s is ready to try%s", version, note),
		Alert:   fmt.Sprintf("kernel %s is ready to try (Update screen: trying it reboots the router)", version),
	}, nil
}

// cleanUpKernels purges the kernel packages this installed that nothing
// needs any more -- never one it didn't install, so never the image's.
func (s *System) cleanUpKernels(state kernelState, keep map[string]bool) ([]string, error) {
	var removed []string
	list := state.installed()
	for _, pkg := range slices.Clone(list) {
		if keep[pkg[min(len(kernelPackagePrefix), len(pkg)):]] { // package[len(PACKAGE_PREFIX):]
			continue
		}
		if _, err := s.kernelRun("apt-get", "purge", "-y", "-q", "--", pkg); err != nil {
			return removed, err
		}
		list = slices.DeleteFunc(list, func(p string) bool { return p == pkg })
		state.setInstalled(list)
		removed = append(removed, pkg)
	}
	if len(removed) > 0 {
		if err := s.saveKernelState(state); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// RecordKernelCheck notes the last check's message for the Update
// screen.
func (s *System) RecordKernelCheck(message string, isError bool) error {
	state := s.loadKernelState()
	check := config.NewMap()
	check.Set("at", s.kernelNow())
	check.Set("message", message)
	check.Set("error", isError)
	state.m.Set("last_check", check)
	return s.saveKernelState(state)
}

// --- the initrd: the image's own, its kernel modules exchanged -----------------------
//
// The archive is edited, never unpacked: unpacking it on the router would
// have to recreate its setuid mount (refused in fr-kernel-prepare's
// sandbox, RestrictSUIDSGID) and its device nodes. Every entry but the
// old kernel's modules is copied as it is, byte for byte.

var newcMagic = []byte("070701")

const newcTrailer = "TRAILER!!!"

func pad4(n int) int { return (4 - n%4) % 4 }

// cut is data[a:b] as Python slices: clamped, empty when b <= a.
func cut(data []byte, a, b int) []byte {
	a, b = min(max(a, 0), len(data)), min(max(b, 0), len(data))
	if b <= a {
		return nil
	}
	return data[a:b]
}

// pyHexInt is int(b, 16): surrounding whitespace, an optional 0x and
// single underscores between digits allowed.
func pyHexInt(b []byte) (int, error) {
	text := strings.TrimSpace(string(b))
	digits := text
	if len(digits) > 2 && (digits[:2] == "0x" || digits[:2] == "0X") {
		digits = strings.TrimPrefix(digits[2:], "_")
	}
	ok := digits != "" && digits[0] != '_' && digits[len(digits)-1] != '_' && !strings.Contains(digits, "__")
	n, err := strconv.ParseInt(strings.ReplaceAll(digits, "_", ""), 16, 64)
	if !ok || err != nil {
		return 0, &RaisedError{"ValueError", "invalid literal for int() with base 16: " + pyBytesRepr(b)}
	}
	return int(n), nil
}

// pyBytesRepr is repr(b) for a bytes value.
func pyBytesRepr(b []byte) string {
	var sb strings.Builder
	quote := byte('\'')
	if bytes.IndexByte(b, '\'') >= 0 && bytes.IndexByte(b, '"') < 0 {
		quote = '"'
	}
	sb.WriteByte('b')
	sb.WriteByte(quote)
	for _, c := range b {
		switch {
		case c == quote || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&sb, `\x%02x`, c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte(quote)
	return sb.String()
}

type newcEntry struct {
	raw  []byte
	name string
	ino  int
}

// readNewc is the entries of one newc cpio archive at offset (its
// trailer left out), and where it ends.
func readNewc(data []byte, offset int) ([]newcEntry, int, error) {
	var entries []newcEntry
	for {
		if !bytes.Equal(cut(data, offset, offset+6), newcMagic) {
			return nil, 0, updateErr("not a newc cpio archive at byte %d", offset)
		}
		var fields [13]int
		for i := range fields {
			v, err := pyHexInt(cut(data, offset+6+8*i, offset+14+8*i))
			if err != nil {
				return nil, 0, err
			}
			fields[i] = v
		}
		namesize, filesize := fields[11], fields[6]
		nameStart := offset + 110
		name := string(cut(data, nameStart, nameStart+namesize-1))
		dataStart := nameStart + namesize + pad4(110+namesize)
		end := dataStart + filesize + pad4(filesize)
		if name == newcTrailer {
			return entries, end, nil
		}
		entries = append(entries, newcEntry{raw: cut(data, offset, end), name: name, ino: fields[0]})
		offset = end
	}
}

func newcHeader(name string, mode int, data []byte, ino int, mtime int64) []byte {
	encoded := append([]byte(name), 0)
	nlink := 1
	if mode&0o040000 != 0 {
		nlink = 2
	}
	var b bytes.Buffer
	b.Write(newcMagic)
	for _, v := range []int64{int64(ino), int64(mode), 0, 0, int64(nlink), mtime, int64(len(data)), 0, 0, 0, 0,
		int64(len(encoded)), 0} {
		fmt.Fprintf(&b, "%08X", v)
	}
	b.Write(encoded)
	b.Write(make([]byte, pad4(110+len(encoded))))
	b.Write(data)
	b.Write(make([]byte, pad4(len(data))))
	return b.Bytes()
}

// SplitInitrd is an initrd as (its uncompressed early archives, e.g.
// microcode, as they are; its main archive, decompressed). decompress
// runs a program on data (zstd and xz, which Go has no reader for).
func SplitInitrd(blob []byte, decompress func(program string, data []byte) ([]byte, error)) ([]byte, []byte, error) {
	offset := 0
	for bytes.Equal(cut(blob, offset, offset+6), newcMagic) {
		_, end, err := readNewc(blob, offset)
		if err != nil {
			return nil, nil, err
		}
		offset = end
		for offset < len(blob) && blob[offset] == 0 { // padding between archives
			offset++
		}
	}
	early, compressed := cut(blob, 0, offset), cut(blob, offset, len(blob))
	switch {
	case bytes.HasPrefix(compressed, []byte{0x1f, 0x8b}):
		r, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, nil, &RaisedError{"BadGzipFile", err.Error()}
		}
		main, err := io.ReadAll(io.LimitReader(r, maxInitrdBytes+1))
		if err != nil {
			return nil, nil, &RaisedError{"BadGzipFile", err.Error()}
		}
		if len(main) > maxInitrdBytes {
			return nil, nil, updateErr("the initrd's main archive is larger than %d MiB", maxInitrdBytes>>20)
		}
		return early, main, nil
	case bytes.HasPrefix(compressed, []byte("\xfd7zXZ\x00")):
		main, err := decompress("xz", compressed)
		if err != nil {
			return nil, nil, updateErr("xz could not decompress the initrd: %v", err)
		}
		return early, main, nil
	case bytes.HasPrefix(compressed, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		main, err := decompress("zstd", compressed)
		if err != nil {
			return nil, nil, updateErr("zstd could not decompress the initrd: %v", err)
		}
		return early, main, nil
	}
	return nil, nil, updateErr("the initrd's main archive is in a compression this router can't read")
}

// Decompress runs program -dc on data (zstd, xz): its output, at most
// maxInitrdBytes.
func Decompress(program string, data []byte) ([]byte, error) {
	cmd := exec.Command(program, "-dc")
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	main, rerr := io.ReadAll(io.LimitReader(out, maxInitrdBytes+1))
	werr := cmd.Wait()
	switch {
	case rerr != nil:
		return nil, rerr
	case len(main) > maxInitrdBytes:
		return nil, fmt.Errorf("more than %d MiB", maxInitrdBytes>>20)
	case werr != nil:
		return nil, fmt.Errorf("%v: %s", werr, strings.TrimSpace(stderr.String()))
	}
	return main, nil
}

func bareModule(relative string) string { return moduleSuffix.ReplaceAllString(relative, "") }

// pathLess is Python's PurePath ordering: component by component.
func pathLess(a, b string) int {
	return slices.Compare(strings.Split(a, "/"), strings.Split(b, "/"))
}

// buildInitrd writes base (the image's initrd) with its kernel modules
// exchanged for the same ones -- and what they depend on -- from modules
// (/usr/lib/modules/<version>), to out.
func (s *System) buildInitrd(base, modules, version, out string) error {
	if !isFile(base) {
		return updateErr("no initrd to start from: %s", base)
	}
	if !isFile(filepath.Join(modules, "modules.dep")) {
		return updateErr("no modules for kernel %s in %s", version, modules)
	}
	blob, err := os.ReadFile(base)
	if err != nil {
		return err
	}
	early, main, err := SplitInitrd(blob, s.decompress())
	if err != nil {
		return err
	}
	entries, _, err := readNewc(main, 0)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(entries, func(e newcEntry) bool { return e.name == "scripts/live" }) {
		return updateErr("%s has no live-boot: no kernel could find the router's root with it", base)
	}
	olds := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.name, "usr/lib/modules/") && strings.Count(e.name, "/") >= 3 {
			olds[strings.Split(e.name, "/")[3]] = true
		}
	}
	if len(olds) != 1 {
		return updateErr("%s has %d kernels' modules, not one", base, len(olds))
	}
	var old string
	for k := range olds {
		old = k
	}
	oldPrefix := "usr/lib/modules/" + old
	wanted := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.name, oldPrefix+"/") && moduleSuffix.MatchString(e.name) {
			wanted[bareModule(e.name[len(oldPrefix)+1:])] = true
		}
	}

	// The new kernel's module files and dependencies, by bare name.
	depText, err := os.ReadFile(filepath.Join(modules, "modules.dep"))
	if err != nil {
		return err
	}
	available, depends := map[string]string{}, map[string][]string{}
	for _, line := range config.PySplitlines(string(depText)) {
		module, deps, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		available[bareModule(module)] = module
		var list []string
		for _, d := range config.PySplit(deps) {
			list = append(list, bareModule(d))
		}
		depends[bareModule(module)] = list
	}
	chosen := map[string]bool{}
	var todo []string
	for m := range wanted {
		if _, ok := available[m]; ok {
			todo = append(todo, m)
		}
	}
	for len(todo) > 0 {
		m := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if chosen[m] {
			continue
		}
		chosen[m] = true
		for _, d := range depends[m] {
			if _, ok := available[d]; ok {
				todo = append(todo, d)
			}
		}
	}

	tmp, err := os.MkdirTemp("", "fros-initrd-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	tree := filepath.Join(tmp, "lib", "modules", version)
	if err := os.MkdirAll(tree, 0o777); err != nil {
		return err
	}
	for m := range chosen {
		target := filepath.Join(tree, available[m])
		if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
			return err
		}
		if err := copyPlain(filepath.Join(modules, available[m]), target); err != nil {
			return err
		}
	}
	for _, name := range moduleIndex {
		if isFile(filepath.Join(modules, name)) {
			if err := copyPlain(filepath.Join(modules, name), filepath.Join(tree, name)); err != nil {
				return err
			}
		}
	}
	if _, err := s.kernelRun("depmod", "-b", tmp, version); err != nil {
		return err
	}

	var archive bytes.Buffer
	ino := 0
	present := map[string]bool{}
	for _, e := range entries {
		if e.name == oldPrefix || strings.HasPrefix(e.name, oldPrefix+"/") {
			continue
		}
		archive.Write(e.raw)
		ino = max(ino, e.ino)
		present[e.name] = true
	}
	ino++
	st, err := os.Stat(base)
	if err != nil {
		return err
	}
	mtime := st.ModTime().Unix()
	var paths []string
	err = filepath.WalkDir(tree, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != tree {
			rel, _ := filepath.Rel(tree, path)
			paths = append(paths, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	slices.SortFunc(paths, pathLess)
	newPrefix := "usr/lib/modules/" + version
	var added [][]byte
	for _, rel := range append([]string{""}, paths...) {
		name, path := newPrefix, tree
		if rel != "" {
			name, path = newPrefix+"/"+rel, filepath.Join(tree, rel)
		}
		if isDir(path) {
			added = append(added, newcHeader(name, 0o040755, nil, ino, mtime))
		} else {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			added = append(added, newcHeader(name, 0o100644, data, ino, mtime))
		}
		ino++
	}
	if !present["usr/lib/modules"] {
		added = slices.Insert(added, 0, newcHeader("usr/lib/modules", 0o040755, nil, ino, mtime))
	}
	for _, a := range added {
		archive.Write(a)
	}
	archive.Write(newcHeader(newcTrailer, 0, nil, 0, 0))

	dir := filepath.Dir(out)
	if err := os.MkdirAll(filepath.Dir(dir), 0o777); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	var packed bytes.Buffer
	packed.Write(early)
	zw, _ := gzip.NewWriterLevel(&packed, 6)
	if _, err := zw.Write(archive.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	tmpOut := filepath.Join(dir, "."+filepath.Base(out)+".tmp")
	if err := os.WriteFile(tmpOut, packed.Bytes(), 0o666); err != nil {
		return err
	}
	if err := os.Rename(tmpOut, out); err != nil {
		return err
	}
	written, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	_, wmain, err := SplitInitrd(written, s.decompress())
	if err != nil {
		return err
	}
	got, _, err := readNewc(wmain, 0)
	if err != nil {
		return err
	}
	names := map[string]bool{}
	for _, e := range got {
		names[e.name] = true
	}
	if !names[newPrefix+"/modules.dep"] || !names["scripts/live"] {
		return updateErr("%s came out without live-boot or the modules of kernel %s", out, version)
	}
	return nil
}

func (s *System) decompress() func(string, []byte) ([]byte, error) {
	if s.Decompress != nil {
		return s.Decompress
	}
	return Decompress
}

// copyPlain is shutil.copyfile: the bytes, a new file 0666 less umask.
func copyPlain(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// --- what the Update screen shows, and its "Try it" ---------------------------------

// KernelOverview is the update-helper's kernel_status: plain values,
// in 1.x's order; a nil pointer is None.
type KernelOverview struct {
	Available bool    `json:"available"`
	Running   string  `json:"running"`
	Boot      *string `json:"boot"`
	State     *string `json:"state"`
	Staged    *string `json:"staged"`
	Intact    *bool   `json:"intact"`
	Summary   string  `json:"summary"`
	Ready     *string `json:"ready"`
	// LastCheck is the state file's last_check as it is (JSON).
	LastCheck jsonRaw `json:"last_check"`
}

// jsonRaw is a JSON value written as it is.
type jsonRaw string

func (r jsonRaw) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// KernelOverview is what the Update screen shows. No hashing of the
// staged files here (review v0.2.1 #4): GRUB checks them at every boot,
// firewall-cli kernel status on request.
func (s *System) KernelOverview() (KernelOverview, error) {
	st := s.KernelStatus(false)
	state := s.loadKernelState()
	prepared := mapString(state.prepared(), "version")
	busy := st.Staged == prepared && (stagedLive(st.State) || st.State == KernelFailed)
	o := KernelOverview{
		Available: st.Available, Running: st.Running, Boot: optional(st.Boot), State: optional(st.State),
		Staged: optional(st.Staged), Summary: st.Summary(), LastCheck: "null",
	}
	if prepared != "" && !busy {
		o.Ready = &prepared
	}
	if v, ok := state.m.Get("last_check"); ok {
		text, err := config.PyJSON(v, -1, false)
		if err != nil {
			return o, err
		}
		o.LastCheck = jsonRaw(text)
	}
	return o, nil
}

// TryPreparedKernel stages the prepared kernel for a trial at the next
// boot and is its version; the caller reboots.
func (s *System) TryPreparedKernel(bootDir string) (string, error) {
	prepared := s.loadKernelState().prepared()
	version := mapString(prepared, "version")
	if version == "" {
		return "", updateErr("no kernel is ready to try")
	}
	st := s.KernelStatus(true)
	if st.Staged == version && st.State == KernelFailed {
		return "", updateErr("kernel %s already failed its trial boot here", version)
	}
	// ROADMAP SEC-23: what works now must work again on its trial boot.
	expect := s.CurrentExpectations()
	return version, s.StageKernel(mapString(prepared, "kernel"), mapString(prepared, "initrd"), version, bootDir,
		expect)
}
