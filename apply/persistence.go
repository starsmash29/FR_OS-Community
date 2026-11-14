package apply

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// Keeping a live-booted router's state across reboots (frfw.persistence).
//
// The FR_OS image is a Debian live system: without persistence everything
// written after boot (config.yaml, the admin password, enabled services,
// SSH host keys, DHCP leases) lives in RAM and is gone at the next boot,
// and first boot runs again, with a new password. Debian's live-boot has
// a standard answer: with `persistence` on the kernel command line it
// looks for a filesystem labelled "persistence" holding a
// persistence.conf and overlays what that file lists onto the running
// system. FR_OS persists the whole root (`/ union`), so a live-booted
// router behaves like an installed one.
//
// Nothing here touches an existing partition: on the boot medium it only
// appends a new partition in unallocated space after the last one, and
// a whole disk with partitions is taken only when told to wipe it. The
// tools are util-linux's and e2fsprogs' (sfdisk, partx, blkid,
// mkfs.ext4); the kernel only re-reads the new partition (`partx
// --add`, which works while the stick's first partition is mounted).

const (
	persistenceLabel   = "persistence"
	persistenceConf    = "persistence.conf"
	persistenceContent = "/ union\n"
	// persistenceMinBytes is the smallest partition worth creating:
	// config, logs, leases and a couple of update releases fit.
	persistenceMinBytes = 256 * 1024 * 1024
	// alignBytes: partitions start on a 1 MiB boundary.
	alignBytes            = 1024 * 1024
	liveMediumMount       = "/run/live/medium"
	livePersistencePrefix = "/run/live/persistence/"
)

// PersistenceError is a persistence partition that could not be set up;
// nothing was changed unless the message says otherwise.
type PersistenceError struct{ Msg string }

func (e *PersistenceError) Error() string { return e.Msg }

func persistErr(format string, args ...any) error {
	return &PersistenceError{fmt.Sprintf(format, args...)}
}

// PersistenceStatus is the state: live or installed, persistence in use
// or not, and on which devices.
type PersistenceStatus struct {
	Live, Active bool
	// Requested is `persistence` on the kernel's command line.
	Requested bool
	// Devices are the persistence filesystems in use; BootDevice what
	// /run/live/medium is mounted from ("" when it isn't); Labelled the
	// filesystems labelled "persistence".
	Devices    []string
	BootDevice string
	Labelled   []string
}

// Summary is the state in a sentence.
func (st PersistenceStatus) Summary() string {
	switch {
	case !st.Live:
		return "installed system -- changes are kept on its own disk"
	case st.Active:
		return "live system with persistence on " + strings.Join(st.Devices, ", ") + " -- changes survive reboots"
	case len(st.Labelled) > 0 && !st.Requested:
		return "live system booted without the 'persistence' option -- " + strings.Join(st.Labelled, ", ") +
			" is not in use, changes are lost at reboot"
	}
	return "live system without persistence -- changes are lost at reboot"
}

func readOrEmpty(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

type mount struct{ source, target string }

// mountsOf is /proc/mounts' source and target of each line (a space
// is \040 there).
func mountsOf(text string) []mount {
	var out []mount
	for _, line := range config.PySplitlines(text) {
		parts := config.PySplit(line)
		if len(parts) >= 2 {
			out = append(out, mount{parts[0], strings.ReplaceAll(parts[1], `\040`, " ")})
		}
	}
	return out
}

// diskRun runs a disk tool; check refuses a non-zero exit.
func (s *System) diskRun(argv []string, stdin string, check bool) (string, error) {
	res, err := s.Run(Cmd{Argv: argv, Stdin: stdin, Timeout: 120 * time.Second})
	var te *TimeoutError
	switch {
	case errors.Is(err, ErrNotFound):
		return "", persistErr("%s is not installed", argv[0])
	case errors.As(err, &te):
		return "", persistErr("%s timed out", argv[0])
	case err != nil:
		return "", err
	}
	if check && res.Code != 0 {
		out := res.Stderr
		if out == "" {
			out = res.Stdout
		}
		return "", persistErr("%s failed: %s", strings.Join(argv, " "), config.PyStrip(out))
	}
	return res.Stdout, nil
}

// labelledDevices are the filesystems labelled "persistence" (blkid -L
// only returns one).
func (s *System) labelledDevices() []string {
	out, err := s.diskRun([]string{"blkid", "-t", "LABEL=" + persistenceLabel, "-o", "device"}, "", false)
	if err != nil {
		return nil
	}
	var found []string
	for _, line := range config.PySplitlines(out) {
		if l := config.PyStrip(line); l != "" {
			found = append(found, l)
		}
	}
	return found
}

// Persistence is the state now.
func (s *System) Persistence() PersistenceStatus {
	args := config.PySplit(readOrEmpty(s.Paths.Cmdline))
	mounts := mountsOf(readOrEmpty(s.Paths.Mounts))
	st := PersistenceStatus{Live: slices.Contains(args, "boot=live"), Requested: slices.Contains(args, "persistence")}
	for _, m := range mounts {
		if strings.HasPrefix(m.target, livePersistencePrefix) && !slices.Contains(st.Devices, m.source) {
			st.Devices = append(st.Devices, m.source)
		}
	}
	slices.Sort(st.Devices)
	for _, m := range mounts {
		if m.target == liveMediumMount {
			st.BootDevice = m.source
			break
		}
	}
	st.Active = st.Live && len(st.Devices) > 0
	if st.Live {
		st.Labelled = s.labelledDevices()
	}
	return st
}

// devNode is where device's node is (Paths.Dev in place of /dev).
func (s *System) devNode(device string) string {
	if rest, ok := strings.CutPrefix(device, "/dev/"); ok {
		return filepath.Join(s.Paths.Dev, rest)
	}
	return device
}

// parentDisk: /dev/sda1 is on /dev/sda; a whole disk is itself.
func (s *System) parentDisk(device string) string {
	node := filepath.Join(s.Paths.SysBlock, filepath.Base(device))
	if exists(filepath.Join(node, "partition")) {
		if target, err := filepath.EvalSymlinks(node); err == nil {
			return "/dev/" + filepath.Base(filepath.Dir(target))
		}
	}
	return device
}

// diskUnsuitable is why disk can't hold a persistence partition, ""
// when it can.
func (s *System) diskUnsuitable(disk string) string {
	name := filepath.Base(disk)
	for _, p := range []string{"sr", "loop", "ram", "zram"} {
		if strings.HasPrefix(name, p) {
			if p == "sr" {
				return disk + " is a CD/DVD device"
			}
			return disk + " is a virtual device"
		}
	}
	ro := filepath.Join(s.Paths.SysBlock, name, "ro")
	if exists(ro) && config.PyStrip(readOrEmpty(ro)) == "1" {
		return disk + " is read-only"
	}
	return ""
}

type freeSpace struct {
	table               string
	start, size, sector *big.Int
	lastPartition       int
}

var (
	bigAlign = big.NewInt(alignBytes)
	zero     = big.NewInt(0)
)

// intOf is int(v) of a JSON number, ok false where Python's int() would
// raise.
func intOf(v config.Value) (*big.Int, bool) {
	switch x := v.(type) {
	case *big.Int:
		return x, true
	case bool:
		if x {
			return big.NewInt(1), true
		}
		return big.NewInt(0), true
	case float64:
		f := new(big.Float).SetFloat64(x)
		if f.IsInf() {
			return nil, false
		}
		n, _ := f.Int(nil)
		return n, true
	case string:
		return config.PyInt(x)
	}
	return nil, false
}

// freeSpaceAfterLastPartition is where a new partition fits at the end
// of the disk, from `sfdisk --json` and the disk's size.
func freeSpaceAfterLastPartition(sfdiskJSON string, diskBytes *big.Int) (*freeSpace, error) {
	v, err := config.ParseJSONLastWins([]byte(sfdiskJSON))
	top, _ := v.(*config.Map)
	var table *config.Map
	if err == nil && top != nil {
		if t, ok := top.Get("partitiontable"); ok {
			table, _ = t.(*config.Map)
			if table == nil {
				return nil, errors.New("the partition table is no object") // 1.x: AttributeError
			}
		}
	}
	if table == nil {
		return nil, persistErr("unreadable partition table")
	}
	label, _ := table.Get("label")
	l, _ := label.(string)
	if l != "dos" && l != "gpt" {
		return nil, persistErr("unsupported partition table type %s", config.Repr(label))
	}
	sector := big.NewInt(512)
	if sv, ok := table.Get("sectorsize"); ok {
		if sector, ok = intOf(sv); !ok {
			return nil, errors.New("the sector size is no number")
		}
	}
	var partitions []config.Value
	if pv, ok := table.Get("partitions"); ok {
		if partitions, ok = pv.([]config.Value); !ok {
			return nil, errors.New("the partitions are no list")
		}
	}
	end := big.NewInt(0)
	for _, p := range partitions {
		m, _ := p.(*config.Map)
		if m == nil {
			return nil, errors.New("a partition is no object")
		}
		sv, ok1 := m.Get("start")
		nv, ok2 := m.Get("size")
		start, ok3 := sv.(*big.Int)
		size, ok4 := nv.(*big.Int)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, errors.New("a partition without its start and size")
		}
		if e := new(big.Int).Add(start, size); e.Cmp(end) > 0 {
			end = e
		}
	}
	end.Mul(end, sector)
	usableEnd := new(big.Int).Set(diskBytes)
	if l == "gpt" { // GPT keeps a backup header in the last 33 sectors
		usableEnd.Sub(usableEnd, new(big.Int).Mul(big.NewInt(33), sector))
	}
	// Python's -(-end // ALIGN) * ALIGN and floor division.
	start := new(big.Int).Neg(end)
	start.Div(start, bigAlign) // Div is Euclidean: floor for a positive divisor
	start.Neg(start).Mul(start, bigAlign)
	size := new(big.Int).Sub(usableEnd, start)
	size.Div(size, bigAlign).Mul(size, bigAlign)
	if l == "dos" && len(partitions) >= 4 {
		return nil, persistErr("the MBR partition table already has four partitions")
	}
	if size.Sign() < 0 {
		size = zero
	}
	return &freeSpace{table: l, start: start, size: size, sector: sector, lastPartition: len(partitions)}, nil
}

func (s *System) diskBytes(disk string) (*big.Int, error) {
	// blockdev has no `--`; disk was checked by the caller.
	out, err := s.diskRun([]string{"blockdev", "--getsize64", disk}, "", true)
	if err != nil {
		return nil, err
	}
	n, ok := config.PyInt(out)
	if !ok {
		return nil, fmt.Errorf("invalid literal for int() with base 10: %s", config.Repr(config.PyStrip(out)))
	}
	return n, nil
}

// partitionPath: /dev/sda -> /dev/sda3, /dev/nvme0n1 or /dev/mmcblk0 ->
// ...p3.
func partitionPath(disk string, number int) string {
	if last := disk[len(disk)-1]; last >= '0' && last <= '9' {
		return fmt.Sprintf("%sp%d", disk, number)
	}
	return fmt.Sprintf("%s%d", disk, number)
}

var blockDeviceRE = regexp.MustCompile(`\A/dev/[A-Za-z0-9][A-Za-z0-9_-]{0,62}\z`)

// BlockDevice is a plain device node, /dev/sda, /dev/nvme0n1,
// /dev/mmcblk0p1, never an option or a path trick (security-lessons F1:
// before it reaches sfdisk, wipefs or mkfs, which also get `--`).
func BlockDevice(v string) (string, error) {
	if !blockDeviceRE.MatchString(v) {
		return "", refused("invalid block device %s", v)
	}
	return v, nil
}

func checkDevicePath(device string) error {
	if _, err := BlockDevice(device); err != nil {
		return &PersistenceError{err.Error()}
	}
	return nil
}

// makePersistenceFilesystem formats partition and writes its
// persistence.conf.
func (s *System) makePersistenceFilesystem(partition string) error {
	if err := checkDevicePath(partition); err != nil {
		return err
	}
	if _, err := s.diskRun([]string{"mkfs.ext4", "-q", "-F", "-L", persistenceLabel, "--", partition}, "", true); err != nil {
		return err
	}
	mountpoint, err := os.MkdirTemp("", "fros-persistence-")
	if err != nil {
		return err
	}
	// Only the empty directory is removed: if the unmount failed, what
	// is on the new filesystem stays (decisions.md, "phase 4f-2a").
	defer os.Remove(mountpoint)
	if _, err := s.diskRun([]string{"mount", "--", partition, mountpoint}, "", true); err != nil {
		return err
	}
	werr := writeText(filepath.Join(mountpoint, persistenceConf), persistenceContent)
	if _, err := s.diskRun([]string{"umount", "--", mountpoint}, "", false); err != nil {
		return err
	}
	return werr
}

// CreatePersistenceOnBootMedium appends a persistence partition in the
// unallocated space at the end of disk (the medium FR_OS booted from)
// and returns it.
func (s *System) CreatePersistenceOnBootMedium(disk string) (string, error) {
	if err := checkDevicePath(disk); err != nil {
		return "", err
	}
	if reason := s.diskUnsuitable(disk); reason != "" {
		return "", &PersistenceError{reason}
	}
	table, err := s.diskRun([]string{"sfdisk", "--json", "--", disk}, "", true)
	if err != nil {
		return "", err
	}
	size, err := s.diskBytes(disk)
	if err != nil {
		return "", err
	}
	space, err := freeSpaceAfterLastPartition(table, size)
	if err != nil {
		return "", err
	}
	if space.size.Cmp(big.NewInt(persistenceMinBytes)) < 0 {
		mib := new(big.Int).Div(space.size, big.NewInt(1<<20))
		return "", persistErr("only %s MiB free after the last partition on %s (need %d MiB) -- use a bigger stick "+
			"or 'firewall-cli persistence create'", mib, disk, persistenceMinBytes>>20)
	}
	partType := "83"
	if space.table == "gpt" {
		partType = "L"
	}
	startSector := new(big.Int).Div(space.start, space.sector)
	if _, err := s.diskRun([]string{"sfdisk", "--append", "--no-reread", "--no-tell-kernel", "--", disk},
		"start="+startSector.String()+", type="+partType+"\n", true); err != nil {
		return "", err
	}
	number := space.lastPartition + 1
	partition := partitionPath(disk, number)
	// The kernel learns of the new partition without re-reading the
	// whole (busy) table.
	if _, err := s.diskRun([]string{"partx", "--add", "--nr", fmt.Sprint(number), "--", disk}, "", false); err != nil {
		return "", err
	}
	if !exists(s.devNode(partition)) {
		if _, err := s.diskRun([]string{"udevadm", "settle"}, "", false); err != nil {
			return "", err
		}
	}
	if !exists(s.devNode(partition)) {
		return "", persistErr("created partition %d on %s, but %s did not appear", number, disk, partition)
	}
	if err := s.makePersistenceFilesystem(partition); err != nil {
		return "", err
	}
	return partition, nil
}

// CreatePersistenceOnDisk makes disk (a whole disk, e.g. an internal
// SSD) a persistence disk: one partition spanning it. A disk with
// partitions only with wipe; one in use never.
func (s *System) CreatePersistenceOnDisk(disk string, wipe bool) (string, error) {
	if err := checkDevicePath(disk); err != nil {
		return "", err
	}
	if s.parentDisk(disk) != disk {
		return "", persistErr("%s is a partition; name the whole disk", disk)
	}
	if reason := s.diskUnsuitable(disk); reason != "" {
		return "", &PersistenceError{reason}
	}
	var mounted []string
	for _, m := range mountsOf(readOrEmpty(s.Paths.Mounts)) {
		if (m.source == disk || s.parentDisk(m.source) == disk) && !slices.Contains(mounted, m.source) {
			mounted = append(mounted, m.source)
		}
	}
	if len(mounted) > 0 {
		slices.Sort(mounted)
		return "", persistErr("%s is in use (%s mounted)", disk, strings.Join(mounted, ", "))
	}
	existing, err := s.diskRun([]string{"sfdisk", "--json", "--", disk}, "", false)
	if err != nil {
		return "", err
	}
	if config.PyStrip(existing) != "" {
		v, err := config.ParseJSONLastWins([]byte(existing))
		if err != nil {
			return "", err // 1.x: json's ValueError
		}
		if hasPartitions(v) && !wipe {
			return "", persistErr("%s already has partitions -- pass --wipe to erase everything on it", disk)
		}
	}
	steps := []struct {
		argv  []string
		stdin string
		check bool
	}{
		{[]string{"wipefs", "--all", "--quiet", "--", disk}, "", true},
		{[]string{"sfdisk", "--quiet", "--", disk}, "label: gpt\n,,L\n", true},
		{[]string{"partx", "--update", "--", disk}, "", false},
		{[]string{"udevadm", "settle"}, "", false},
	}
	for _, step := range steps {
		if _, err := s.diskRun(step.argv, step.stdin, step.check); err != nil {
			return "", err
		}
	}
	partition := partitionPath(disk, 1)
	if !exists(s.devNode(partition)) {
		return "", persistErr("%s did not appear after partitioning %s", partition, disk)
	}
	if err := s.makePersistenceFilesystem(partition); err != nil {
		return "", err
	}
	return partition, nil
}

// hasPartitions is json.loads(existing).get("partitiontable", {}).get("partitions")
// being truthy.
func hasPartitions(v config.Value) bool {
	top, _ := v.(*config.Map)
	if top == nil {
		return false
	}
	t, ok := top.Get("partitiontable")
	if !ok {
		return false
	}
	table, _ := t.(*config.Map)
	if table == nil {
		return false
	}
	p, _ := table.Get("partitions")
	return config.Truthy(p)
}

// PersistenceAuto is the boot-time step (fr-persistence-setup.service):
// the outcome and its device. Outcomes: "not-live", "active", "exists"
// (a labelled filesystem is there but wasn't used: booted without the
// option; nothing is created), "created" (reboot to use it), or
// "skipped: <reason>".
func (s *System) PersistenceAuto() (string, string, error) {
	st := s.Persistence()
	switch {
	case !st.Live:
		return "not-live", "", nil
	case st.Active:
		return "active", st.Devices[0], nil
	case len(st.Labelled) > 0:
		return "exists", st.Labelled[0], nil
	case !st.Requested:
		return "skipped: booted without the 'persistence' option", "", nil
	case st.BootDevice == "":
		return "skipped: the live medium is not mounted", "", nil
	}
	partition, err := s.CreatePersistenceOnBootMedium(s.parentDisk(st.BootDevice))
	var pe *PersistenceError
	if errors.As(err, &pe) {
		return "skipped: " + pe.Msg, "", nil
	}
	if err != nil {
		return "", "", err
	}
	return "created", partition, nil
}
