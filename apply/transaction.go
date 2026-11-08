package apply

import (
	"fmt"
	"strings"
)

// Error is an apply that failed (frfw.transaction.ApplyError). Changed is
// false when it failed before anything changed (the preflight, or reading
// what the reload must carry over); otherwise the journal was rolled back,
// and RolledBack / NotRolledBack say what was and wasn't put back. Its
// text is what the webUI shows the admin, word for word 1.x's.
type Error struct {
	Step          string
	Cause         error
	Changed       bool
	RolledBack    []string
	NotRolledBack []string
}

func (e *Error) Unwrap() error { return e.Cause }

func (e *Error) Error() string {
	cause := causeText(e.Cause)
	if !e.Changed {
		return fmt.Sprintf("Nothing was applied -- %s: %s. The running system is unchanged.", e.Step, cause)
	}
	text := fmt.Sprintf("Apply failed at %s: %s.", e.Step, cause)
	if len(e.RolledBack) > 0 {
		text += " Rolled back to the previous state: " + strings.Join(e.RolledBack, ", ") + "."
	}
	if len(e.NotRolledBack) > 0 {
		text += " NOT rolled back: " + strings.Join(e.NotRolledBack, "; ") + "."
	} else {
		text += " Nothing else was changed."
	}
	return text
}

// Named is an error that names its kind when it has no text of its own:
// 1.x's `str(exc) or type(exc).__name__`.
type Named interface{ Kind() string }

func causeText(err error) string {
	if err == nil {
		return "Exception"
	}
	if s := err.Error(); s != "" {
		return s
	}
	if n, ok := err.(Named); ok {
		return n.Kind()
	}
	return "Exception"
}

type entry struct {
	name   string
	undo   func() error
	whyNot string
}

// Transaction is the undo journal of one apply (frfw.transaction).
type Transaction struct{ entries []entry }

// Begin records, before step name changes anything, how to undo it, or
// a nil undo and why it can't be (reported if it comes to a rollback).
// The step that fails is journalled too: it may have done part of its
// work.
func (t *Transaction) Begin(name string, undo func() error, whyNot string) {
	t.entries = append(t.entries, entry{name, undo, whyNot})
}

// RollBack undoes every journalled step, last first: the firewall,
// journalled first, comes back last, so the router is never without a
// ruleset. An undo that fails is reported by name and the others still
// run. It returns what was rolled back and what wasn't, with why.
func (t *Transaction) RollBack() (done, failed []string) {
	for i := len(t.entries) - 1; i >= 0; i-- {
		e := t.entries[i]
		if e.undo == nil {
			failed = append(failed, fmt.Sprintf("%s (%s)", e.name, e.whyNot))
			continue
		}
		if err := runUndo(e.undo); err != nil {
			failed = append(failed, fmt.Sprintf("%s (%s)", e.name, causeText(err)))
			continue
		}
		done = append(done, e.name)
	}
	t.entries = nil
	return done, failed
}

// runUndo turns a panic into the undo's failure: each undo is
// independent, as 1.x's `except Exception`.
func runUndo(undo func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return undo()
}
