package room

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestCodesRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := NewCode()
		if len(c) != 19 || strings.Count(c, "-") != 3 {
			t.Fatalf("bad code %q", c)
		}
		if seen[c] {
			t.Fatalf("repeated code %q", c)
		}
		seen[c] = true
		for _, typed := range []string{c, strings.ToLower(c), strings.ReplaceAll(c, "-", ""), " " + strings.ReplaceAll(c, "-", " ") + "\t"} {
			got, ok := NormalizeCode(typed)
			if !ok || got != c {
				t.Fatalf("NormalizeCode(%q) = %q, %v; want %q", typed, got, ok, c)
			}
		}
	}
	for _, bad := range []string{"", "ABCD-EFGH-JKMN-PQR", "ABCD-EFGH-JKMN-PQRST", "ABCD-EFGH-JKMN-PQR0", "ABCD-EFGH-JKMN-PQRÉ", "ABCD_EFGH_JKMN_PQRS"} {
		if _, ok := NormalizeCode(bad); ok {
			t.Errorf("NormalizeCode(%q) accepted", bad)
		}
	}
}

func TestSecretFromCode(t *testing.T) {
	code := NewCode()
	a, err := SecretFromCode("app-pair-v1", code)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SecretFromCode("app-pair-v1", strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the same code typed differently gave different secrets")
	}
	if !strings.HasPrefix(a.Topic, "app-pair-v1/") || len(a.Topic) != len("app-pair-v1/")+32 {
		t.Fatalf("topic %q", a.Topic)
	}
	other, _ := SecretFromCode("app-pair-v1", NewCode())
	salted, _ := SecretFromCode("other-app", code)
	if other.Key == a.Key || other.Topic == a.Topic || salted.Key == a.Key {
		t.Fatal("different codes or apps gave the same secret")
	}
	if _, err := SecretFromCode("x", "nope"); err != ErrBadCode {
		t.Fatalf("bad code: %v", err)
	}

	// Toru's derivation (internal/stream/room.go roomSecrets): the same scrypt
	// parameters and split, so Toru's rooms can move onto go-room.
	dk, err := scrypt.Key([]byte(code), []byte("toru-stream-room-v1"), 1<<15, 8, 1, 48)
	if err != nil {
		t.Fatal(err)
	}
	toru, _ := SecretFromCode("toru-stream-room-v1", code)
	if !bytes.Equal(toru.Key[:], dk[:32]) || toru.Topic != "toru-stream-room-v1/"+hex.EncodeToString(dk[32:]) {
		t.Fatal("derivation differs from Toru's")
	}
}

func TestSecretFromKey(t *testing.T) {
	ikm := make([]byte, 32)
	_, _ = rand.Read(ikm)
	a := SecretFromKey("app/mesh/1", ikm, []byte("person|1"))
	if a != SecretFromKey("app/mesh/1", ikm, []byte("person|1")) {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(a.Topic, "app/mesh/1/") {
		t.Fatalf("topic %q", a.Topic)
	}
	for _, o := range []Secret{
		SecretFromKey("app/mesh/1", ikm, []byte("person|2")), // next epoch
		SecretFromKey("app/mesh/2", ikm, []byte("person|1")),
		SecretFromKey("app/mesh/1", append([]byte{ikm[0] ^ 1}, ikm[1:]...), []byte("person|1")),
	} {
		if o.Key == a.Key || o.Topic == a.Topic {
			t.Fatal("different inputs gave the same secret")
		}
	}
}
