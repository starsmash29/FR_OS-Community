package webui

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
)

// signer is itsdangerous 2.2's URLSafeTimedSerializer(secret) with its
// defaults, the format of 1.x's session cookie: an upgrade keeps every
// signed-in browser signed in (phase 3 plan, decision 3).
//
//	payload "." base64(timestamp) "." base64(HMAC-SHA1(key, payload "." timestamp))
//
// The key is SHA1("itsdangerous" + "signer" + secret) (key derivation
// "django-concat"); the payload is the compact JSON, zlib-compressed and
// prefixed with "." when that makes it shorter; base64 is URL-safe
// without padding; the timestamp is whole seconds, big-endian, without
// leading zero bytes.
type signer struct{ key []byte }

func newSigner(secret []byte) signer {
	h := sha1.New()
	h.Write([]byte("itsdangerous"))
	h.Write([]byte("signer"))
	h.Write(secret)
	return signer{key: h.Sum(nil)}
}

var errBadSignature = errors.New("bad signature")

func (s signer) mac(value string) []byte {
	m := hmac.New(sha1.New, s.key)
	m.Write([]byte(value))
	return m.Sum(nil)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// pyB64Decode is itsdangerous's base64_decode: non-ASCII dropped,
// padded to a multiple of four, then Python's urlsafe_b64decode
// (binascii.a2b_base64, not strict): characters outside the alphabet
// are skipped, and decoding stops at the padding that completes a
// quantum.
func pyB64Decode(text string) ([]byte, error) {
	var ascii []byte
	for i := 0; i < len(text); i++ {
		if text[i] < 0x80 {
			ascii = append(ascii, text[i])
		}
	}
	for len(ascii)%4 != 0 {
		ascii = append(ascii, '=')
	}
	var out []byte
	var acc uint32
	quad, pads := 0, 0
	for _, c := range ascii {
		var v uint32
		switch {
		case c == '=':
			if quad >= 2 {
				pads++
				if quad+pads >= 4 {
					return out, nil
				}
			}
			continue
		case c >= 'A' && c <= 'Z':
			v = uint32(c - 'A')
		case c >= 'a' && c <= 'z':
			v = uint32(c-'a') + 26
		case c >= '0' && c <= '9':
			v = uint32(c-'0') + 52
		case c == '-' || c == '+':
			v = 62
		case c == '_' || c == '/':
			v = 63
		default:
			continue
		}
		pads = 0
		acc = acc<<6 | v
		quad++
		switch quad {
		case 2:
			out = append(out, byte(acc>>4))
			acc &= 0xf
		case 3:
			out = append(out, byte(acc>>2))
			acc &= 0x3
		case 4:
			out = append(out, byte(acc))
			acc, quad = 0, 0
		}
	}
	if quad != 0 {
		return nil, errBadSignature // incorrect padding
	}
	return out, nil
}

// dumps signs the compact JSON `payload` at whole second `now`.
func (s signer) dumps(payload []byte, now int64) string {
	body := b64(payload)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(payload)
	w.Close()
	// Go's zlib may pick other bytes than 1.x's C zlib for the same
	// input; both read either (testdata/reference/decisions.md).
	if z.Len() < len(payload)-1 {
		body = "." + b64(z.Bytes())
	}
	value := body + "." + b64(intToBytes(now))
	return value + "." + b64(s.mac(value))
}

func intToBytes(n int64) []byte {
	b := big.NewInt(n).Bytes()
	if len(b) == 0 {
		return []byte{}
	}
	return b
}

// loads is the payload of a value dumps made, if its signature holds
// and it is at most maxAge seconds old at whole second `now`; else an
// error (itsdangerous's BadSignature, BadTimeSignature, SignatureExpired
// or BadPayload: 1.x treats them all as no session).
func (s signer) loads(value string, maxAge, now int64) ([]byte, error) {
	i := strings.LastIndexByte(value, '.')
	if i < 0 {
		return nil, errBadSignature
	}
	signed, sig := value[:i], value[i+1:]
	want, err := pyB64Decode(sig)
	if err != nil || !hmac.Equal(want, s.mac(signed)) {
		return nil, errBadSignature
	}
	j := strings.LastIndexByte(signed, '.')
	if j < 0 {
		return nil, errBadSignature
	}
	payload, stamp := signed[:j], signed[j+1:]
	tsBytes, err := pyB64Decode(stamp)
	if err != nil {
		return nil, errBadSignature
	}
	ts := new(big.Int).SetBytes(tsBytes)
	age := new(big.Int).Sub(big.NewInt(now), ts)
	if age.Cmp(big.NewInt(maxAge)) > 0 || age.Sign() < 0 {
		return nil, errBadSignature
	}
	compressed := strings.HasPrefix(payload, ".")
	if compressed {
		payload = payload[1:]
	}
	data, err := pyB64Decode(payload)
	if err != nil {
		return nil, errBadSignature
	}
	if compressed {
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errBadSignature
		}
		// A cookie is at most a few kB; the signature already holds,
		// so this is our own output, but still bounded.
		data, err = io.ReadAll(io.LimitReader(r, 1<<20))
		if err != nil {
			return nil, errBadSignature
		}
	}
	return data, nil
}
