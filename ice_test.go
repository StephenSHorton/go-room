package room

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestICEListWithoutRelay(t *testing.T) {
	r := NewRelay(RelayConfig{}, "me", nil)
	r.Start() // no CredentialURL: nothing to do
	defer r.Stop()
	if got := r.Servers(); !slices.EqualFunc(got, DefaultSTUN, iceEqual) {
		t.Fatalf("servers = %+v, want STUN only", got)
	}
	if st := r.Status(); st.State != RelayNone {
		t.Fatalf("status %+v", st)
	}
	// TURN URLs alone can't work (TURN needs credentials): still STUN only.
	r2 := NewRelay(RelayConfig{TurnURLs: []string{"turn:relay.example:3478", "http://nope"}}, "me", nil)
	if got := r2.Servers(); len(got) != len(DefaultSTUN) || r2.Status().State != RelayNone || r2.Status().Detail == "" {
		t.Fatalf("turn without credentials: %+v %+v", got, r2.Status())
	}
	if w := WebRTCServers([]ICEServer{{URLs: []string{"turn:x"}, Username: "u", Credential: "c"}}); w[0].Username != "u" || w[0].Credential != "c" || w[0].URLs[0] != "turn:x" {
		t.Fatalf("WebRTCServers = %+v", w)
	}
	if got := CleanICEURLs([]string{" turn:a ", "TURNS:b", "stun:c", "http://d", ""}); !slices.Equal(got, []string{"turn:a", "TURNS:b", "stun:c"}) {
		t.Fatalf("CleanICEURLs = %v", got)
	}
}

func iceEqual(a, b ICEServer) bool {
	return slices.Equal(a.URLs, b.URLs) && a.Username == b.Username && a.Credential == b.Credential
}

// credServer is a TURN REST credential endpoint on 127.0.0.1.
func credServer(t *testing.T, fail *atomic.Bool) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("peer") != "me" {
			http.Error(w, "no peer", http.StatusBadRequest)
			return
		}
		if fail != nil && fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		i := n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"username": "user" + string(rune('0'+i)),
			"password": "pw", // the TURN REST draft's name
			"ttl":      1,
			"uris":     []string{"turn:127.0.0.1:3478?transport=udp", "turns:relay.example:443?transport=tcp", "junk"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func withFastRefresh(t *testing.T) {
	oldMin, oldRetry, oldMax := minRefresh, retryMin, retryMax
	minRefresh, retryMin, retryMax = 50*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { minRefresh, retryMin, retryMax = oldMin, oldRetry, oldMax })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func turnEntry(list []ICEServer) *ICEServer {
	for i := range list {
		if list[i].Username != "" {
			return &list[i]
		}
	}
	return nil
}

func TestRelayCredentialRefresh(t *testing.T) {
	withFastRefresh(t)
	srv, n := credServer(t, nil)
	var changes atomic.Int32
	r := NewRelay(RelayConfig{CredentialURL: srv.URL + "/cred?service=turn"}, "me", func() { changes.Add(1) })
	if st := r.Status(); st.State != RelayPending {
		t.Fatalf("before the first fetch: %+v", st)
	}
	r.Start()
	defer r.Stop()
	waitFor(t, "first credentials", func() bool { return turnEntry(r.Servers()) != nil })
	turn := turnEntry(r.Servers())
	if turn.Username != "user1" || turn.Credential != "pw" {
		t.Fatalf("turn entry %+v", turn)
	}
	if !slices.Equal(turn.URLs, []string{"turn:127.0.0.1:3478?transport=udp", "turns:relay.example:443?transport=tcp"}) {
		t.Fatalf("turn urls %v", turn.URLs)
	}
	if st := r.Status(); st.State != RelayOK || st.Expires == 0 {
		t.Fatalf("status %+v", st)
	}
	// ttl 1 s: refreshed at 80%, before it expires.
	waitFor(t, "a refresh", func() bool { return n.Load() >= 2 })
	waitFor(t, "the new username", func() bool {
		e := turnEntry(r.Servers())
		return e != nil && e.Username != "user1"
	})
	if changes.Load() < 2 {
		t.Fatalf("onChange ran %d times", changes.Load())
	}

	// TurnURLs replace the endpoint's uris.
	r2 := NewRelay(RelayConfig{CredentialURL: srv.URL, TurnURLs: []string{"turns:mine.example:443"}}, "me", nil)
	r2.Start()
	defer r2.Stop()
	waitFor(t, "credentials", func() bool { return turnEntry(r2.Servers()) != nil })
	if u := turnEntry(r2.Servers()).URLs; !slices.Equal(u, []string{"turns:mine.example:443"}) {
		t.Fatalf("turnUrls override: %v", u)
	}
}

func TestRelayFailureKeepsThenDrops(t *testing.T) {
	withFastRefresh(t)
	var fail atomic.Bool
	srv, _ := credServer(t, &fail)
	var offset atomic.Int64
	r := NewRelay(RelayConfig{CredentialURL: srv.URL}, "me", nil)
	r.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	r.Start()
	defer r.Stop()
	waitFor(t, "credentials", func() bool { return turnEntry(r.Servers()) != nil })
	fail.Store(true)
	waitFor(t, "the failure", func() bool { return r.Status().State == RelayError })
	if !strings.Contains(r.Status().Detail, "503") {
		t.Fatalf("detail %q", r.Status().Detail)
	}
	// Past expiry, credentials that can't be refreshed leave the list.
	offset.Store(int64(time.Hour))
	if turnEntry(r.Servers()) != nil {
		t.Fatal("expired credentials still offered")
	}
	if got := r.Servers(); len(got) != len(DefaultSTUN) {
		t.Fatalf("servers %+v", got)
	}
	// It recovers by itself.
	offset.Store(0)
	fail.Store(false)
	waitFor(t, "recovery", func() bool { return r.Status().State == RelayOK })
}

func TestRelayRejectsPlainHTTP(t *testing.T) {
	r := NewRelay(RelayConfig{CredentialURL: "http://relay.example/cred"}, "me", nil)
	if _, err := r.fetch(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("fetch over plain http to a remote host: %v", err)
	}
}

// Kick skips a backoff that grew while the credential source was down.
func TestRelayKick(t *testing.T) {
	oldMin, oldMax := retryMin, retryMax
	retryMin, retryMax = time.Minute, time.Minute
	t.Cleanup(func() { retryMin, retryMax = oldMin, oldMax })
	var up atomic.Bool
	r := NewRelay(RelayConfig{Fetch: func(context.Context) (TURNCreds, error) {
		if !up.Load() {
			return TURNCreds{}, errors.New("hub down")
		}
		return TURNCreds{Username: "1:a", Credential: "c", TTL: time.Hour, URIs: []string{"turn:192.0.2.1:1?transport=udp"}}, nil
	}}, "a", nil)
	r.Start()
	defer r.Stop()
	waitFor(t, "first failure", func() bool { return r.Status().State == RelayError })
	up.Store(true)
	r.Kick()
	waitFor(t, "credentials after a kick", func() bool { return r.Status().State == RelayOK })
}
