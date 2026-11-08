// Package apply makes the system match a config, as one transaction
// (ROADMAP SEC-5, review v0.2.0 R6), as FR_OS 1.x's frfw.provision,
// frfw.transaction and frfw.apply do.
//
// This file and its neighbours are the machinery: the undo journal and
// the error an apply reports (Transaction, Error), what a step captures
// before it changes anything so it can be put back (FileState,
// ServiceState, LinkState), the atomic writes (WritePrivate,
// WriteKeepingOwner), systemctl that doesn't deadlock the boot
// (Systemctl), and loading a ruleset with its backup (ApplyRuleset).
// Every program is run through a Runner, with each value validated and
// `--` before positional ones (security-lessons F1).
package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Cmd is one program run.
type Cmd struct {
	Argv  []string
	Stdin string
	// Env is added to the helper's own environment (nft's TZ=UTC).
	Env     []string
	Timeout time.Duration // 0: none
}

// Result is what a run gave.
type Result struct {
	Stdout, Stderr string
	Code           int
}

// Runner runs a program. ErrNotFound: it isn't installed; ErrTimeout: it
// was killed at its timeout.
type Runner func(Cmd) (Result, error)

var (
	ErrNotFound = errors.New("apply: program not found")
	ErrTimeout  = errors.New("apply: program timed out")
)

// maxOutput bounds what is read from a program: far more than the
// largest ruleset listing.
const maxOutput = 64 << 20

// Run runs the real program.
func Run(c Cmd) (Result, error) {
	ctx := context.Background()
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	if c.Stdin != "" {
		cmd.Stdin = bytes.NewBufferString(c.Stdin)
	}
	var stdout, stderr limited
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		return Result{}, ErrNotFound
	}
	if ctx.Err() != nil {
		return Result{}, ErrTimeout
	}
	if stdout.over || stderr.over {
		return Result{}, fmt.Errorf("%s wrote more than %d bytes", c.Argv[0], maxOutput)
	}
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.Code = exit.ExitCode()
	case err != nil:
		return Result{}, err
	}
	return res, nil
}

type limited struct {
	bytes.Buffer
	over bool
}

func (b *limited) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		b.over = true
		return 0, errors.New("too much output")
	}
	return b.Buffer.Write(p)
}
