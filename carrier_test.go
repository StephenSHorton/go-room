package room

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// heardLog records OnHeard and Seen calls.
type heardLog struct {
	mu   sync.Mutex
	from []string
	addr []netip.AddrPort
}

func (h *heardLog) add(from string, a netip.AddrPort) {
	h.mu.Lock()
	h.from = append(h.from, from)
	h.addr = append(h.addr, a)
	h.mu.Unlock()
}

func (h *heardLog) n() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.from)
}

// addrCarrier is a MemHub carrier that stamps every delivery with a fixed
// source address and records what its legs are told, like the LAN carrier.
type addrCarrier struct {
	inner Carrier
	addr  netip.AddrPort
	seen  *heardLog
}

func (c addrCarrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (Leg, error) {
	l, err := c.inner.Join(topic, func(p []byte, _ netip.AddrPort) { deliver(p, c.addr) }, up)
	if err != nil {
		return nil, err
	}
	return addrLeg{Leg: l, seen: c.seen}, nil
}

type addrLeg struct {
	Leg
	seen *heardLog
}

func (l addrLeg) Seen(m string, a netip.AddrPort) { l.seen.add(m, a) }

func TestOpenManyCarriers(t *testing.T) {
	s := testSecret(t)
	h1, h2 := NewMemHub(), NewMemHub()
	lanAddr := netip.MustParseAddrPort("192.0.2.7:38419")
	var seen, heard heardLog
	got := make(chan Envelope, 8)
	connects := make(chan struct{}, 4)
	a, err := Open(s, "a", SignalOptions{}, h1.Carrier(), h2.Carrier())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(s, "b", SignalOptions{
		OnMsg:     func(e Envelope) { got <- e },
		OnConnect: func() { connects <- struct{}{} },
		OnHeard:   heard.add,
	}, h1.Carrier(), addrCarrier{inner: h2.Carrier(), addr: lanAddr, seen: &seen})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-connects:
		case <-time.After(2 * time.Second):
			t.Fatal("OnConnect didn't fire for each carrier")
		}
	}
	if a.Connected() != 2 || b.Connected() != 2 {
		t.Fatalf("connected %d %d, want 2 2", a.Connected(), b.Connected())
	}
	if err := a.Send("", "n", 1); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.From != "a" {
			t.Fatalf("from %q", e.From)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("message lost")
	}
	// The second carrier's copy is a duplicate: dropped, but still reported
	// to the leg and OnHeard with its address.
	select {
	case e := <-got:
		t.Fatalf("duplicate delivered: %+v", e)
	case <-time.After(150 * time.Millisecond):
	}
	if seen.n() != 1 || heard.n() != 1 || heard.from[0] != "a" || heard.addr[0] != lanAddr || seen.addr[0] != lanAddr {
		t.Fatalf("seen %v heard %v %v", seen.addr, heard.from, heard.addr)
	}

	// One carrier gone: the other still carries.
	h1.mu.Lock()
	legs := append([]*memLeg(nil), h1.subs[s.Topic]...)
	h1.mu.Unlock()
	for _, l := range legs {
		l.Close()
	}
	if err := a.Send("", "n", 2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("message lost with one carrier")
	}
	if _, err := Open(s, "c", SignalOptions{}); err == nil {
		t.Fatal("Open with no carriers")
	}
}

func TestSendNoCarrierUp(t *testing.T) {
	s := testSecret(t)
	h := NewMemHub()
	a, _ := Open(s, "a", SignalOptions{}, h.Carrier())
	a.(*signal).legs[0].Close()
	if a.Connected() != 0 {
		t.Fatal("closed leg counted")
	}
	if err := a.Send("", "n", 1); err != ErrNotConnected {
		t.Fatalf("send with nothing up: %v", err)
	}
	a.Close()
	if err := a.Send("", "n", 1); err != ErrClosed {
		t.Fatalf("send after close: %v", err)
	}
}
