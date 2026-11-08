package apply

// SetEuid makes requireRoot see f's uid (the replay of 1.x's applies
// runs as root's fake).
func SetEuid(f func() int) (restore func()) {
	old := geteuid
	geteuid = f
	return func() { geteuid = old }
}
