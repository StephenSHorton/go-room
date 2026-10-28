// Package room lets two or more copies of an app find each other with no
// account, and then talk directly over WebRTC data channels.
//
// Signaling (presence, offers and answers) is sealed with a key derived
// from a shared secret and goes over one or more carriers: the local
// network (OpenLAN), a hub on one of the app's own machines (NewHub,
// DialHub, with NewTURN and package portmap beside it), or public MQTT
// brokers (package mqtt). Every carrier sees only random bytes on a
// random-looking topic. Once two members have found
// each other, Mesh opens a pion PeerConnection between them, binds it to each
// side's ed25519 identity with a signed-fingerprint handshake, and hands the
// app one reliable ordered message channel plus on-demand byte streams.
//
// It was extracted from Toru's rooms (internal/stream/room.go and ice.go).
package room

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Room code alphabet: no 0/O, 1/I/L, so it reads back unambiguously.
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// CodeLen is the number of symbols in a room code: 16 of 31 is about 79 bits.
const CodeLen = 16

// NewCode returns a fresh random room code, formatted XXXX-XXXX-XXXX-XXXX.
func NewCode() string {
	b := make([]byte, CodeLen)
	out := make([]byte, 0, CodeLen)
	for len(out) < CodeLen {
		if _, err := rand.Read(b); err != nil {
			panic(err) // crypto/rand never fails on supported platforms
		}
		for _, v := range b {
			// Rejection sampling keeps every symbol equally likely.
			if v < byte(256/len(codeAlphabet)*len(codeAlphabet)) && len(out) < CodeLen {
				out = append(out, codeAlphabet[int(v)%len(codeAlphabet)])
			}
		}
	}
	return formatCode(string(out))
}

func formatCode(raw string) string {
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(raw[i])
	}
	return sb.String()
}

// NormalizeCode accepts a code typed or pasted any way (lower case, spaces,
// missing dashes) and returns its canonical form.
func NormalizeCode(in string) (string, bool) {
	var raw strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case r < 128 && strings.IndexByte(codeAlphabet, byte(r)) >= 0:
			raw.WriteRune(r)
		default:
			return "", false
		}
	}
	if raw.Len() != CodeLen {
		return "", false
	}
	return formatCode(raw.String()), true
}

// ErrBadCode is returned for a string that isn't a room code.
var ErrBadCode = errors.New("that isn't a room code (16 letters and numbers, like ABCD-EFGH-JKMN-PQRS)")

// Secret is what members of one room share: the key every envelope is
// sealed with, and the broker topic they meet on. Topic is not secret on its
// own (brokers see it), but it is derived from the same secret, so it names
// nobody. Callers may rewrite Topic's prefix (keeping the derived suffix) to
// stay on an existing wire format; Toru's is "toru/v1/".
type Secret struct {
	Key   [32]byte
	Topic string
}

// SecretFromCode derives a room's secret from a room code (any spelling
// NormalizeCode accepts): scrypt(code, salt = app), as Toru does, so guessing
// codes from a captured topic or message is expensive on top of the ~79-bit
// code space. The first 32 bytes are the sealing key; the topic is
// app + "/" + hex(the next 16).
func SecretFromCode(app, code string) (Secret, error) {
	canon, ok := NormalizeCode(code)
	if !ok {
		return Secret{}, ErrBadCode
	}
	dk, err := scrypt.Key([]byte(canon), []byte(app), 1<<15, 8, 1, 48)
	if err != nil {
		return Secret{}, err
	}
	var s Secret
	copy(s.Key[:], dk[:32])
	s.Topic = app + "/" + hex.EncodeToString(dk[32:])
	return s, nil
}

// SecretFromKey derives a room's secret from a high-entropy key (32 random
// bytes or more), such as a secret every device of one person holds:
// HKDF-SHA256(ikm, salt = app, info), 48 bytes, split as in SecretFromCode.
// It is fast, so never feed it something a person typed: use SecretFromCode.
func SecretFromKey(app string, ikm, info []byte) Secret {
	dk, err := hkdf.Key(sha256.New, ikm, []byte(app), string(info), 48)
	if err != nil {
		panic(err) // only for a length HKDF can't produce; 48 always fits
	}
	var s Secret
	copy(s.Key[:], dk[:32])
	s.Topic = app + "/" + hex.EncodeToString(dk[32:])
	return s
}
