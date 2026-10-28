package room

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func testSecret(t *testing.T) Secret {
	t.Helper()
	s, err := SecretFromCode("go-room-test", NewCode())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// collector records what a core hands up.
type collector struct {
	mu   sync.Mutex
	msgs []Envelope
	rtc  []Envelope
}

func (c *collector) msg(e Envelope) { c.mu.Lock(); c.msgs = append(c.msgs, e); c.mu.Unlock() }
func (c *collector) rtcMsg(e Envelope) {
	c.mu.Lock()
	c.rtc = append(c.rtc, e)
	c.mu.Unlock()
}
func (c *collector) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs), len(c.rtc)
}

func TestSealOpen(t *testing.T) {
	s := testSecret(t)
	a, _ := newCore(s, "a", SignalOptions{})
	var got collector
	b, _ := newCore(s, "b", SignalOptions{OnMsg: got.msg})
	b.setRTC(got.rtcMsg)
	c, _ := newCore(s, "c", SignalOptions{})

	sealed, err := a.seal("", "hello", map[string]int{"n": 7})
	if err != nil {
		t.Fatal(err)
	}
	// A broker sees nothing readable.
	if bytes.Contains(sealed, []byte("hello")) || bytes.Contains(sealed, []byte(`"a"`)) {
		t.Fatal("plaintext in the sealed payload")
	}
	env, ok := b.open(sealed)
	if !ok || env.From != "a" || env.Type != "hello" || env.V != 1 || env.ID == "" {
		t.Fatalf("open: %+v %v", env, ok)
	}
	body, err := Decode[map[string]int](env)
	if err != nil || body["n"] != 7 {
		t.Fatalf("body %v %v", body, err)
	}
	if _, ok := a.open(sealed); ok {
		t.Fatal("a member got its own message back")
	}

	// Addressed to b only: c drops it.
	direct, _ := a.seal("b", "x", nil)
	if _, ok := c.open(direct); ok {
		t.Fatal("c opened a message for b")
	}
	if _, ok := b.open(direct); !ok {
		t.Fatal("b couldn't open its message")
	}

	// Another room's key, or a flipped byte: dropped.
	other, _ := newCore(testSecret(t), "b", SignalOptions{})
	if _, ok := other.open(sealed); ok {
		t.Fatal("opened with the wrong key")
	}
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 1
	if _, ok := b.open(bad); ok {
		t.Fatal("opened a tampered payload")
	}
	if _, ok := b.open(sealed[:10]); ok {
		t.Fatal("opened a short payload")
	}

	// rtc.* goes to the mesh hook, everything else to OnMsg; dupes once.
	rtc, _ := a.seal("b", MsgOffer, sdpBody{Session: "s", SDP: "v=0"})
	b.receive(sealed)
	b.receive(sealed) // the second broker's copy
	b.receive(rtc)
	b.receive(rtc)
	if m, r := got.counts(); m != 1 || r != 1 {
		t.Fatalf("delivered %d messages and %d rtc, want 1 and 1", m, r)
	}
}

func TestMessageAge(t *testing.T) {
	s := testSecret(t)
	a, _ := newCore(s, "a", SignalOptions{})
	b, _ := newCore(s, "b", SignalOptions{MaxAge: time.Minute})
	now := time.Now()
	for _, tc := range []struct {
		skew time.Duration
		ok   bool
	}{{0, true}, {-50 * time.Second, true}, {50 * time.Second, true}, {-2 * time.Minute, false}, {2 * time.Minute, false}} {
		a.now = func() time.Time { return now.Add(tc.skew) }
		p, _ := a.seal("", "t", nil)
		if _, ok := b.open(p); ok != tc.ok {
			t.Errorf("skew %v: opened %v, want %v", tc.skew, ok, tc.ok)
		}
	}
	// The default is 2 minutes.
	d, _ := newCore(s, "d", SignalOptions{})
	if d.maxAge != DefaultMaxAge || DefaultMaxAge != 2*time.Minute {
		t.Fatalf("default max age %v", d.maxAge)
	}
}

func TestDedupePrunes(t *testing.T) {
	s := testSecret(t)
	a, _ := newCore(s, "a", SignalOptions{})
	var got collector
	b, _ := newCore(s, "b", SignalOptions{OnMsg: got.msg})
	start := time.Now()
	clock := start
	a.now = func() time.Time { return clock }
	b.now = func() time.Time { return clock }
	first, _ := a.seal("", "t", nil)
	firstEnv, _ := b.open(first)
	b.receive(first)
	// Much later (and past the cap) old ids are forgotten; the age check
	// still drops a replay of them.
	clock = start.Add(5 * time.Minute)
	for range seenCap + 1 {
		p, _ := a.seal("", "t", nil)
		b.receive(p)
	}
	b.mu.Lock()
	_, kept := b.seen[firstEnv.ID]
	n := len(b.seen)
	b.mu.Unlock()
	if kept || n > seenCap+1 {
		t.Fatalf("seen not pruned: kept=%v len=%d", kept, n)
	}
	before, _ := got.counts()
	b.receive(first)
	if after, _ := got.counts(); after != before {
		t.Fatal("an old replay got through")
	}
}

func TestMemHub(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	var taps [][]byte
	var tapMu sync.Mutex
	hub.Tap = func(topic string, p []byte) {
		if topic != s.Topic {
			t.Errorf("published on %q", topic)
		}
		tapMu.Lock()
		taps = append(taps, p)
		tapMu.Unlock()
	}
	got := make(chan Envelope, 8)
	connected := make(chan struct{}, 1)
	a := hub.Open(s, "a", SignalOptions{})
	b := hub.Open(s, "b", SignalOptions{OnMsg: func(e Envelope) { got <- e }, OnConnect: func() { connected <- struct{}{} }})
	other := hub.Open(testSecret(t), "x", SignalOptions{OnMsg: func(e Envelope) { t.Errorf("other room got %+v", e) }})
	defer other.Close()
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnect didn't fire")
	}
	if a.Connected() != 1 || b.Topic() != s.Topic || b.Self() != "b" {
		t.Fatal("signaler state")
	}
	for i := range 3 {
		if err := a.Send("", "n", i); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		select {
		case e := <-got:
			if n, _ := Decode[int](e); n != i {
				t.Fatalf("got %d, want %d (order)", n, i)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("message lost")
		}
	}
	// A broker replaying the same bytes changes nothing.
	tapMu.Lock()
	replay := taps[0]
	tapMu.Unlock()
	hub.Publish(s.Topic, replay)
	select {
	case e := <-got:
		t.Fatalf("replay delivered: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	raw, _ := json.Marshal(Envelope{V: 1, ID: "x", From: "a", Type: "n", At: time.Now().UnixMilli()})
	hub.Publish(s.Topic, raw) // unsealed: dropped
	b.Close()
	if err := b.Send("", "n", 1); err != ErrClosed {
		t.Fatalf("send after close: %v", err)
	}
	if err := a.Send("", "n", 9); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		t.Fatalf("closed signaler got %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}
