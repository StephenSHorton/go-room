package room

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every LAN test runs on MemLAN or on 127.0.0.1 sockets with explicit
// targets: no wildcard bind, no broadcast, no multicast.

func memLANNode(t *testing.T, n *MemLAN, addr string, now func() time.Time) *LAN {
	t.Helper()
	l, err := OpenLAN(LANConfig{
		Conn:    n.Conn(netip.MustParseAddrPort(addr)),
		Targets: func() []netip.AddrPort { return []netip.AddrPort{n.Broadcast()} },
		Now:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

func recvEnv(t *testing.T, ch chan Envelope, what string) Envelope {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: nothing arrived", what)
		return Envelope{}
	}
}

func noEnv(t *testing.T, ch chan Envelope, what string) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("%s: got %+v", what, e)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestLANBroadcastThenUnicast(t *testing.T) {
	n := NewMemLAN()
	var mu sync.Mutex
	var deliveries []netip.AddrPort
	n.Drop = func(_, to netip.AddrPort) bool {
		mu.Lock()
		deliveries = append(deliveries, to)
		mu.Unlock()
		return false
	}
	s := testSecret(t)
	la := memLANNode(t, n, "10.0.0.1:38419", nil)
	lb := memLANNode(t, n, "10.0.0.2:38419", nil)
	lc := memLANNode(t, n, "10.0.0.3:38419", nil)
	gotA, gotB, gotC := make(chan Envelope, 8), make(chan Envelope, 8), make(chan Envelope, 8)
	var heard atomic.Value
	a, _ := Open(s, "a", SignalOptions{OnMsg: func(e Envelope) { gotA <- e }, OnHeard: func(from string, ap netip.AddrPort) { heard.Store(from + "@" + ap.String()) }}, la.Carrier())
	b, _ := Open(s, "b", SignalOptions{OnMsg: func(e Envelope) { gotB <- e }}, lb.Carrier())
	c, _ := Open(s, "c", SignalOptions{OnMsg: func(e Envelope) { gotC <- e }}, lc.Carrier())
	defer a.Close()
	defer b.Close()
	defer c.Close()
	if a.Connected() != 1 {
		t.Fatal("LAN leg not up")
	}
	// b to everyone: a and c hear it, and a learns where b is.
	if err := b.Send("", "presence", nil); err != nil {
		t.Fatal(err)
	}
	recvEnv(t, gotA, "a")
	recvEnv(t, gotC, "c")
	if h, _ := heard.Load().(string); h != "b@10.0.0.2:38419" {
		t.Fatalf("OnHeard %q", h)
	}
	// a to b: unicast now, so only b's address gets a datagram.
	mu.Lock()
	deliveries = nil
	mu.Unlock()
	if err := a.Send("b", "direct", nil); err != nil {
		t.Fatal(err)
	}
	if e := recvEnv(t, gotB, "b"); e.Type != "direct" {
		t.Fatalf("b got %s", e.Type)
	}
	noEnv(t, gotC, "c (unicast to b)")
	mu.Lock()
	for _, d := range deliveries {
		if d != netip.MustParseAddrPort("10.0.0.2:38419") {
			t.Fatalf("unicast reached %v", d)
		}
	}
	mu.Unlock()
	// a to c, whom it hasn't heard: broadcast, and only c opens it.
	if err := a.Send("c", "direct", nil); err != nil {
		t.Fatal(err)
	}
	recvEnv(t, gotC, "c")
	noEnv(t, gotB, "b (for c)")

	// Too big for a datagram.
	if err := a.Send("", "big", string(make([]byte, MaxLANDatagram))); err != ErrTooBigDatagram {
		t.Fatalf("oversize: %v", err)
	}
}

func TestLANTagWindows(t *testing.T) {
	n := NewMemLAN()
	s := testSecret(t)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	la := memLANNode(t, n, "10.0.0.1:38419", nil) // the sender's tag is always now
	lb := memLANNode(t, n, "10.0.0.2:38419", now)
	got := make(chan Envelope, 8)
	a, _ := Open(s, "a", SignalOptions{}, la.Carrier())
	b, _ := Open(s, "b", SignalOptions{OnMsg: func(e Envelope) { got <- e }}, lb.Carrier())
	defer a.Close()
	defer b.Close()
	other, _ := Open(testSecret(t), "x", SignalOptions{OnMsg: func(e Envelope) { got <- e }}, lb.Carrier())
	defer other.Close()

	// Tags differ by topic and by window.
	if lanTag(s.Topic, 1) == lanTag(s.Topic, 2) || lanTag(s.Topic, 1) == lanTag("other", 1) {
		t.Fatal("tags don't vary")
	}
	// b's clock is one window ahead: the sender's tag is b's previous
	// window, still accepted.
	clock.Store(time.Now().Add(lanWindow * time.Second).UnixNano())
	_ = a.Send("", "t", nil)
	recvEnv(t, got, "previous window")
	noEnv(t, got, "other room")
	// b's clock is one window behind (the sender's is ahead): the sender's
	// tag is b's next window, also accepted.
	clock.Store(time.Now().Add(-lanWindow * time.Second).UnixNano())
	_ = a.Send("", "t", nil)
	recvEnv(t, got, "next window")
	// Two windows ahead: dropped unopened.
	clock.Store(time.Now().Add(2 * lanWindow * time.Second).UnixNano())
	_ = a.Send("", "t", nil)
	noEnv(t, got, "stale window")
}

// A host that captures a member's datagram and sends it again from its own
// address doesn't become where that member is.
func TestLANReplayDoesntMoveAMember(t *testing.T) {
	n := NewMemLAN()
	s := testSecret(t)
	var mu sync.Mutex
	var captured []byte
	la := memLANNode(t, n, "10.0.0.1:38419", nil)
	lb := memLANNode(t, n, "10.0.0.2:38419", nil)
	attacker := n.Conn(netip.MustParseAddrPort("10.0.0.66:38419"))
	defer attacker.Close()
	go func() {
		buf := make([]byte, MaxLANDatagram)
		for {
			k, _, err := attacker.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			if captured == nil {
				captured = append([]byte(nil), buf[:k]...)
			}
			mu.Unlock()
		}
	}()
	var heard []string
	var hmu sync.Mutex
	a, _ := Open(s, "a", SignalOptions{OnHeard: func(from string, ap netip.AddrPort) {
		hmu.Lock()
		heard = append(heard, from+"@"+ap.String())
		hmu.Unlock()
	}}, la.Carrier())
	b, _ := Open(s, "b", SignalOptions{}, lb.Carrier())
	defer a.Close()
	defer b.Close()
	if err := b.Send("", "presence", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "captured", func() bool { mu.Lock(); defer mu.Unlock(); return captured != nil })
	waitFor(t, "a heard b", func() bool { hmu.Lock(); defer hmu.Unlock(); return len(heard) == 1 })
	mu.Lock()
	replay := captured
	mu.Unlock()
	for range 3 {
		_, _ = attacker.WriteTo(replay, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.0.0.1:38419")))
	}
	time.Sleep(150 * time.Millisecond)
	hmu.Lock()
	defer hmu.Unlock()
	if len(heard) != 1 || heard[0] != "b@10.0.0.2:38419" {
		t.Fatalf("heard %v", heard)
	}
	leg := a.(*signal).legs[0].(*lanLeg)
	leg.mu.Lock()
	got := leg.addrs["b"]
	leg.mu.Unlock()
	if got != netip.MustParseAddrPort("10.0.0.2:38419") {
		t.Fatalf("b's address moved to %v", got)
	}
}

func TestLANRateAndJunk(t *testing.T) {
	n := NewMemLAN()
	s := testSecret(t)
	fixed := time.Now()
	lb, err := OpenLAN(LANConfig{
		Conn:    n.Conn(netip.MustParseAddrPort("10.0.0.2:38419")),
		Targets: func() []netip.AddrPort { return nil },
		MaxRate: 3,
		Now:     func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Close()
	la := memLANNode(t, n, "10.0.0.1:38419", func() time.Time { return fixed })
	var count atomic.Int32
	a, _ := Open(s, "a", SignalOptions{}, la.Carrier())
	b, _ := Open(s, "b", SignalOptions{OnMsg: func(Envelope) { count.Add(1) }}, lb.Carrier())
	defer a.Close()
	defer b.Close()
	raw := n.Conn(netip.MustParseAddrPort("10.0.0.9:1"))
	defer raw.Close()
	dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.0.0.2:38419"))
	_, _ = raw.WriteTo([]byte("junk"), dst)
	_, _ = raw.WriteTo(append([]byte("GR1"), make([]byte, 64)...), dst) // unknown tag
	for range 10 {
		_ = a.Send("", "t", nil)
	}
	time.Sleep(200 * time.Millisecond)
	if c := count.Load(); c != 3 {
		t.Fatalf("opened %d in one second, want 3", c)
	}
	// With no targets, a broadcast has nowhere to go.
	if err := b.Send("", "t", nil); err != ErrNotConnected {
		t.Fatalf("send with no targets: %v", err)
	}
}

func TestDirectedBroadcast(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.20/24": "192.168.1.255",
		"10.1.2.3/8":      "10.255.255.255",
		"172.16.5.4/20":   "172.16.15.255",
	} {
		if got := directedBroadcast(netip.MustParsePrefix(in)); got.String() != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// Two members connect over the LAN carrier on real 127.0.0.1 sockets, each
// targeting the other's port as its "broadcast".
func TestMeshOverLAN(t *testing.T) {
	ca, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cb, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	aAddr, bAddr := addrPortOf(ca.LocalAddr()), addrPortOf(cb.LocalAddr())
	la, err := OpenLAN(LANConfig{Conn: ca, Targets: func() []netip.AddrPort { return []netip.AddrPort{bAddr} }})
	if err != nil {
		t.Fatal(err)
	}
	defer la.Close()
	lb, err := OpenLAN(LANConfig{Conn: cb, Targets: func() []netip.AddrPort { return []netip.AddrPort{aAddr} }})
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Close()
	s := testSecret(t)
	sa, _ := Open(s, "dev-a", SignalOptions{}, la.Carrier())
	sb, _ := Open(s, "dev-b", SignalOptions{}, lb.Carrier())
	a := newNodeOn(t, sa, "dev-a", nodeOpts{})
	b := newNodeOn(t, sb, "dev-b", nodeOpts{})
	pa, pb := pair(t, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pa.Messages().Send(ctx, []byte("over the LAN")); err != nil {
		t.Fatal(err)
	}
	msg, err := pb.Messages().Recv(ctx)
	if err != nil || string(msg) != "over the LAN" {
		t.Fatalf("recv %q %v", msg, err)
	}
}
