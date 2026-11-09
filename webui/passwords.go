package webui

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// What a password must not be (security-lessons G6), as 1.x's
// frfw.passwords: shorter than MinPasswordLength, one of the 10,000 most
// common passwords (also with trailing digits and punctuation removed),
// too repetitive, or containing the account's username. The list is
// local: nothing is sent anywhere to check a password.

// MinPasswordLength is the shortest password accepted (review v0.2.1
// FR-NEW-007: a passphrase of a few words).
const MinPasswordLength = 12

//go:embed data/common-passwords.txt
var commonPasswordText string

var commonPasswords = sync.OnceValue(func() map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(commonPasswordText, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line != "" && !strings.HasPrefix(line, "#") {
			set[line] = true
		}
	}
	return set
})

// trailingStem is the password without what _TRAILING
// (`[\d\W_]+\Z`) matches: trailing digits, non-word characters and '_'.
func trailingStem(s string) string {
	end := len(s)
	for end > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:end])
		if r != '_' && isPyWord(r) && !unicode.IsDigit(r) {
			break
		}
		end -= size
	}
	return s[:end]
}

// isPyWord is Python's \w for str patterns: '_' and what str.isalnum
// calls alphanumeric (letters and every kind of number).
func isPyWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// passwordProblem is why password is refused, or "".
func passwordProblem(password, username string) string {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Sprintf("Password must be at least %d characters", MinPasswordLength)
	}
	lowered := strings.ToLower(password)
	common := commonPasswords()
	stem := trailingStem(lowered)
	if common[lowered] || (utf8.RuneCountInString(stem) >= 4 && common[stem]) {
		return "That password is one of the most common ones attackers try first -- choose another"
	}
	distinct := map[rune]bool{}
	for _, r := range lowered {
		distinct[r] = true
	}
	if len(distinct) <= 2 {
		return "That password is too repetitive -- choose another"
	}
	if username != "" && utf8.RuneCountInString(username) >= 3 && strings.Contains(lowered, strings.ToLower(username)) {
		return "The password must not contain the username"
	}
	return ""
}
