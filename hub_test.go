package room

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// Every hub test listens on 127.0.0.1 and dials only there.

type testHub struct {
	hub  *Hub
	addr string
	pub  ed25519.PublicKey

	mu      sync.Mutex
	members map[string]ed25519.PublicKey // the "certified" devices
}

func (th *testHub) certify(id string, pub ed25519.PublicKey) {
	th.mu.Lock()
	th.members[id] = pub
	th.mu.Unlock()
}

func (th *testHub) revoke(id string) {
	th.mu.Lock()
	delete(th.members, id)
	th.mu.Unlock()
}

func (th *testHub) expect(id string, pub ed25519.PublicKey) error {
	if id != "srv" || !pub.Equal(th.pub) {
		return errors.New("not our server")
	}
	return nil
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func newTestHub(t *testing.T, edit func(*HubConfig)) *testHub {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	th := &testHub{pub: pub, members: map[string]ed25519.PublicKey{}}
	cfg := HubConfig{
		Self:     "srv",
		Identity: KeyIdentity(key),
		Authorize: func(id string, pub ed25519.PublicKey) error {
			th.mu.Lock()
			defer th.mu.Unlock()
			if want, ok := th.members[id]; !ok || !want.Equal(pub) {
				return errors.New("not certified")
			}
			return nil
		},
		Limits: HubLimits{FailBackoff: -1},
		Logf:   t.Logf,
	}
	if edit != nil {
		edit(&cfg)
	}
	h, err := NewHub(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln := listenLoopback(t)
	go func() { _ = h.Serve(ln) }()
	t.Cleanup(h.Close)
	th.hub, th.addr = h, ln.Addr().String()
	return th
}

// member makes a certified member and dials the hub.
func (th *testHub) member(t *testing.T, id string) (*HubClient, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	th.certify(id, pub)
	ident := KeyIdentity(key)
	c := DialHub(HubDialConfig{Self: id, Identity: &ident, Addrs: func() []string { return []string{th.addr} }, Expect: th.expect, Logf: t.Logf})
	t.Cleanup(c.Close)
	return c, key
}

func (th *testHub) guest(t *testing.T, topic string) *HubClient {
	t.Helper()
	c := DialHub(HubDialConfig{GuestTopic: topic, Addrs: func() []string { return []string{th.addr} }, Logf: t.Logf})
	t.Cleanup(c.Close)
	return c
}

func fastHubRetry(t *testing.T) {
	old := hubRetryMin
	hubRetryMin = 20 * time.Millisecond
	t.Cleanup(func() { hubRetryMin = old })
}

// openOn opens a signaler that collects what arrives.
func openOn(t *testing.T, s Secret, id string, cs ...Carrier) (Signaler, chan Envelope) {
	t.Helper()
	got := make(chan Envelope, 16)
	sig, err := Open(s, id, SignalOptions{OnMsg: func(e Envelope) { got <- e }}, cs...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sig.Close)
	return sig, got
}

// sendUntil sends until got receives (a subscription may still be on its
// way), then returns what arrived.
func sendUntil(t *testing.T, sig Signaler, typ string, got chan Envelope) Envelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = sig.Send("", typ, nil)
		select {
		case e := <-got:
			return e
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("%s never arrived", typ)
	return Envelope{}
}

// Two members connect through a real hub on 127.0.0.1 and a Mesh runs on
// top unchanged.
func TestMeshOverHub(t *testing.T) {
	th := newTestHub(t, nil)
	s := testSecret(t)
	// The server's own room is what makes the topic one members may use.
	openOn(t, s, "srv", th.hub.Local())
	ca, _ := th.member(t, "dev-a")
	cb, _ := th.member(t, "dev-b")
	waitFor(t, "both connected", func() bool { return ca.Up() && cb.Up() })
	if id, pub := ca.Server(); id != "srv" || !pub.Equal(th.pub) || ca.Addr() != th.addr {
		t.Fatalf("server %q %v at %q", id, pub, ca.Addr())
	}
	sa, _ := Open(s, "dev-a", SignalOptions{}, ca.Carrier())
	sb, _ := Open(s, "dev-b", SignalOptions{}, cb.Carrier())
	a := newNodeOn(t, sa, "dev-a", nodeOpts{})
	b := newNodeOn(t, sb, "dev-b", nodeOpts{})
	// The sub frames race the first want; Connect again until it lands.
	go func() {
		for range 50 {
			if b.mesh.Peer("dev-a") != nil {
				return
			}
			b.mesh.Connect("dev-a")
			time.Sleep(100 * time.Millisecond)
		}
	}()
	pb := waitUp(t, b)
	pa := waitUp(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pa.Messages().Send(ctx, []byte("via the hub")); err != nil {
		t.Fatal(err)
	}
	if msg, err := pb.Messages().Recv(ctx); err != nil || string(msg) != "via the hub" {
		t.Fatalf("recv %q %v", msg, err)
	}
	if n := len(th.hub.Peers()); n != 2 {
		t.Fatalf("hub sees %d peers", n)
	}
}

func TestHubTopicsAndLocal(t *testing.T) {
	th := newTestHub(t, nil)
	s := testSecret(t)
	_, srvGot := openOn(t, s, "srv", th.hub.Local())
	ca, _ := th.member(t, "dev-a")
	waitFor(t, "connected", ca.Up)
	sa, _ := openOn(t, s, "dev-a", ca.Carrier())
	// Member to the server's own room and back.
	if e := sendUntil(t, sa, "hi", srvGot); e.From != "dev-a" {
		t.Fatalf("server got %+v", e)
	}
	// A topic the server has no room on: the subscription is refused, so
	// nothing is carried.
	other := testSecret(t)
	ox, _ := openOn(t, other, "dev-a", ca.Carrier())
	cb, _ := th.member(t, "dev-b")
	waitFor(t, "b connected", cb.Up)
	_, oyGot := openOn(t, other, "dev-b", cb.Carrier())
	time.Sleep(200 * time.Millisecond)
	_ = ox.Send("", "x", nil)
	noEnv(t, oyGot, "a topic the hub doesn't carry")
}

func rawHello(t *testing.T, addr string, alpn []string, hello func(x []byte) hubHello) (int, error) {
	t.Helper()
	tc, err := tls.Dial("tcp4", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: alpn}) //nolint:gosec // test
	if err != nil {
		return 0, err
	}
	defer tc.Close()
	cs := tc.ConnectionState()
	x, err := cs.ExportKeyingMaterial(hubExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if hello != nil {
		_ = writeFrame(tc, frameHello, marshal(hello(x)))
	}
	_ = tc.SetReadDeadline(time.Now().Add(7 * time.Second))
	buf := make([]byte, 64)
	return tc.Read(buf)
}

func TestHubRefusesWithoutReply(t *testing.T) {
	old := hubHelloTimeout
	hubHelloTimeout = 500 * time.Millisecond
	defer func() { hubHelloTimeout = old }()
	th := newTestHub(t, nil)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	alpn := []string{HubALPN}
	sign := func(id string, k ed25519.PrivateKey) func(x []byte) hubHello {
		return func(x []byte) hubHello {
			return hubHello{V: 1, ID: id, Pub: k.Public().(ed25519.PublicKey), Sig: ed25519.Sign(k, hubSigPayload(hubClientContext, x, id))}
		}
	}
	for name, h := range map[string]func(x []byte) hubHello{
		"unknown key": sign("dev-x", key),
		"bad signature": func(x []byte) hubHello {
			hh := sign("dev-x", key)(x)
			hh.Sig[0] ^= 1
			return hh
		},
		"guest, no window": func([]byte) hubHello { return hubHello{V: 1, Guest: true, Topic: "irori-pair-v1/abc"} },
		"wrong version":    func(x []byte) hubHello { hh := sign("dev-x", key)(x); hh.V = 2; return hh },
		"no hello":         nil,
	} {
		n, err := rawHello(t, th.addr, alpn, h)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("%s: read %d bytes, %v; want a silent close", name, n, err)
		}
	}
	// Certified, and signing the wrong context: still nothing.
	th.certify("dev-x", pub)
	n, err := rawHello(t, th.addr, alpn, func(x []byte) hubHello {
		return hubHello{V: 1, ID: "dev-x", Pub: pub, Sig: ed25519.Sign(key, hubSigPayload(hubServerContext, x, "dev-x"))}
	})
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("server context: read %d, %v", n, err)
	}
	// The right signature gets a welcome.
	if n, err := rawHello(t, th.addr, alpn, sign("dev-x", key)); n == 0 || err != nil {
		t.Errorf("good hello: read %d, %v", n, err)
	}
	// No ALPN, or TLS 1.2: no session at all.
	if _, err := rawHello(t, th.addr, nil, nil); err == nil {
		t.Error("handshake without ALPN completed")
	}
	if tc, err := tls.Dial("tcp4", th.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: alpn}); err == nil { //nolint:gosec // test
		tc.Close()
		t.Error("TLS 1.2 accepted")
	}
}

func TestHubExpectAndDrop(t *testing.T) {
	fastHubRetry(t)
	th := newTestHub(t, nil)
	// A member that doesn't recognise the server never comes up.
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	th.certify("dev-a", pub)
	ident := KeyIdentity(key)
	wrong := DialHub(HubDialConfig{Self: "dev-a", Identity: &ident, Addrs: func() []string { return []string{th.addr} },
		Expect: func(string, ed25519.PublicKey) error { return errors.New("who are you") }})
	defer wrong.Close()
	noExpect := DialHub(HubDialConfig{Self: "dev-a", Identity: &ident, Addrs: func() []string { return []string{th.addr} }})
	defer noExpect.Close()
	time.Sleep(300 * time.Millisecond)
	if wrong.Up() || noExpect.Up() {
		t.Fatal("came up without a matching Expect")
	}

	// Revoke: Drop closes it, and Authorize keeps it out.
	cb, _ := th.member(t, "dev-b")
	waitFor(t, "connected", cb.Up)
	if err := cb.OpenGuest(context.Background(), "pair/1", time.Minute); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "guest topic open", func() bool {
		th.hub.mu.Lock()
		defer th.hub.mu.Unlock()
		return th.hub.guests["pair/1"] != nil
	})
	th.revoke("dev-b")
	th.hub.Drop("dev-b")
	waitFor(t, "dropped", func() bool { return !cb.Up() })
	time.Sleep(200 * time.Millisecond)
	if cb.Up() {
		t.Fatal("revoked member reconnected")
	}
	th.hub.mu.Lock()
	_, open := th.hub.guests["pair/1"]
	th.hub.mu.Unlock()
	if open {
		t.Fatal("revoked member's guest topic stayed open")
	}
}

func TestHubGuests(t *testing.T) {
	fastHubRetry(t)
	th := newTestHub(t, nil)
	pair := testSecret(t)
	ca, _ := th.member(t, "dev-a")
	waitFor(t, "connected", ca.Up)
	// A guest before the window opens is refused and keeps retrying.
	g := th.guest(t, pair.Topic)
	time.Sleep(150 * time.Millisecond)
	if g.Up() {
		t.Fatal("guest admitted with no window")
	}
	if err := ca.OpenGuest(context.Background(), pair.Topic, time.Minute); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "guest admitted", g.Up)
	if id, _ := g.Server(); id != "srv" {
		t.Fatalf("guest sees server %q", id)
	}
	sa, aGot := openOn(t, pair, "dev-a", ca.Carrier())
	sg, gGot := openOn(t, pair, "guest-b", g.Carrier())
	if e := sendUntil(t, sg, "pair.hello", aGot); e.From != "guest-b" {
		t.Fatalf("member got %+v", e)
	}
	if e := sendUntil(t, sa, "pair.ok", gGot); e.From != "dev-a" {
		t.Fatalf("guest got %+v", e)
	}
	// The guest may not reach any other topic, even an open one.
	other := testSecret(t)
	_ = th.hub.OpenGuest(other.Topic, time.Minute)
	og, _ := openOn(t, other, "guest-b", g.Carrier())
	_, oaGot := openOn(t, other, "dev-a", ca.Carrier())
	time.Sleep(200 * time.Millisecond)
	_ = og.Send("", "x", nil)
	noEnv(t, oaGot, "guest on a second topic")
	// Two guest topics per member, no more.
	_ = ca.OpenGuest(context.Background(), "pair/2", time.Minute)
	_ = ca.OpenGuest(context.Background(), "pair/3", time.Minute)
	time.Sleep(200 * time.Millisecond)
	th.hub.mu.Lock()
	_, three := th.hub.guests["pair/3"]
	th.hub.mu.Unlock()
	if three {
		t.Fatal("a third guest topic opened")
	}
	// Closing the window drops the guest, and it can't come back.
	ca.CloseGuest(pair.Topic)
	waitFor(t, "guest dropped", func() bool { return !g.Up() })
	time.Sleep(150 * time.Millisecond)
	if g.Up() {
		t.Fatal("guest back after its window closed")
	}
	// A guest can't open windows of its own.
	if err := g.OpenGuest(context.Background(), "x", time.Minute); err == nil {
		t.Fatal("guest opened a guest topic")
	}
}

func TestHubGuestExpires(t *testing.T) {
	th := newTestHub(t, nil)
	if err := th.hub.OpenGuest("pair/x", 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	g := th.guest(t, "pair/x")
	waitFor(t, "guest admitted", g.Up)
	waitFor(t, "expired", func() bool { return !g.Up() })
}

// A device at home with only the code reaches a member away from home: the
// server bridges the open guest topic between its LAN and the hub.
func TestHubBridgesGuestTopicToLAN(t *testing.T) {
	n := NewMemLAN()
	bridge := memLANNode(t, n, "10.0.0.20:38419", nil)
	th := newTestHub(t, func(c *HubConfig) { c.Bridge = bridge })
	pair := testSecret(t)
	away, _ := th.member(t, "dev-a")
	waitFor(t, "connected", away.Up)
	if err := away.OpenGuest(context.Background(), pair.Topic, time.Minute); err != nil {
		t.Fatal(err)
	}
	home := memLANNode(t, n, "10.0.0.30:38419", nil)
	sa, aGot := openOn(t, pair, "dev-a", away.Carrier())
	sb, bGot := openOn(t, pair, "new-b", home.Carrier())
	if e := sendUntil(t, sb, "pair.hello", aGot); e.From != "new-b" {
		t.Fatalf("away member got %+v", e)
	}
	if e := sendUntil(t, sa, "pair.ok", bGot); e.From != "dev-a" {
		t.Fatalf("home device got %+v", e)
	}
	// Mesh topics aren't bridged.
	mesh := testSecret(t)
	_, _ = openOn(t, mesh, "srv", th.hub.Local())
	sm, _ := openOn(t, mesh, "dev-a", away.Carrier())
	_, lanGot := openOn(t, mesh, "new-b", home.Carrier())
	time.Sleep(200 * time.Millisecond)
	_ = sm.Send("", "x", nil)
	noEnv(t, lanGot, "mesh topic over the bridge")
}

func TestHubTURNAndSplit(t *testing.T) {
	// One port number for everything: TCP split between the hub and TURN,
	// UDP for TURN.
	ln := listenLoopback(t)
	hubLn, turnLn := SplitTCP(ln)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcfg := TURNConfig{UDP: udp, TCP: turnLn, RelayIP: netip.MustParseAddr("127.0.0.1")}
	_, _ = rand.Read(tcfg.Key[:])
	ts, err := NewTURN(tcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	th := &testHub{pub: pub, members: map[string]ed25519.PublicKey{}}
	h, err := NewHub(HubConfig{Self: "srv", Identity: KeyIdentity(key), TURN: ts, Limits: HubLimits{FailBackoff: -1},
		Authorize: func(id string, p ed25519.PublicKey) error {
			th.mu.Lock()
			defer th.mu.Unlock()
			if !p.Equal(th.members[id]) {
				return errors.New("no")
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve(hubLn) }()
	defer h.Close()
	th.hub, th.addr = h, ln.Addr().String()

	ca, _ := th.member(t, "dev-a")
	waitFor(t, "connected", ca.Up)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	creds, err := ca.TURN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if creds.TTL < DefaultTURNTTL-time.Minute || len(creds.URIs) != 3 || creds.URIs[1] != "turn:"+th.addr+"?transport=udp" {
		t.Fatalf("creds %v %v", creds.TTL, creds.URIs)
	}
	// The same credentials allocate over TURN-over-TCP on the hub's port.
	tcp, err := net.Dial("tcp4", th.addr)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: th.addr, STUNServerAddr: th.addr, Username: creds.Username,
		Password: creds.Credential, Realm: DefaultTURNRealm, Conn: turn.NewSTUNConn(tcp), LoggerFactory: quietLogs()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.Listen(); err != nil {
		t.Fatal(err)
	}
	if mapped, err := cl.SendBindingRequest(); err != nil || mapped == nil {
		t.Fatalf("STUN over TCP: %v %v", mapped, err)
	}
	relay, err := cl.Allocate()
	if err != nil {
		t.Fatalf("allocate over TCP: %v", err)
	}
	_ = relay.Close()

	// A guest's credentials are its own and narrower.
	pair := testSecret(t)
	_ = h.OpenGuest(pair.Topic, time.Minute)
	g := th.guest(t, pair.Topic)
	waitFor(t, "guest", g.Up)
	gc, err := g.TURN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gc.TTL > time.Minute || gc.Username == creds.Username {
		t.Fatalf("guest creds %q %v", gc.Username, gc.TTL)
	}
	if _, err := allocate(t, udp.LocalAddr().String(), gc); err != nil {
		t.Fatalf("guest allocate: %v", err)
	}
	// Closing the window revokes the guest's relay.
	h.CloseGuest(pair.Topic)
	waitFor(t, "guest dropped", func() bool { return !g.Up() })
	waitFor(t, "guest TURN revoked", func() bool {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return len(ts.guests) == 0
	})

	// Anything that is neither TLS nor STUN is closed at once.
	junk, err := net.Dial("tcp4", th.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer junk.Close()
	_, _ = junk.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	_ = junk.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Closed with unread bytes, so Windows may report a reset instead of EOF.
	var ne net.Error
	if n, err := junk.Read(make([]byte, 16)); n != 0 || err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("junk got %d bytes, %v", n, err)
	}
}

func TestHubNoTURN(t *testing.T) {
	th := newTestHub(t, nil)
	ca, _ := th.member(t, "dev-a")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ca.TURN(ctx); err == nil {
		t.Fatal("TURN from a hub without a relay")
	}
}

func TestHubLimits(t *testing.T) {
	th := newTestHub(t, func(c *HubConfig) { c.Limits.Members = 1; c.Limits.TopicsPerConn = 1 })
	ca, _ := th.member(t, "dev-a")
	waitFor(t, "a", ca.Up)
	cb, _ := th.member(t, "dev-b")
	time.Sleep(200 * time.Millisecond)
	if cb.Up() {
		t.Fatal("second member past Members=1")
	}
	// One topic per connection: a second room on the same hub client gets
	// nothing.
	s1, s2 := testSecret(t), testSecret(t)
	_, srv1 := openOn(t, s1, "srv", th.hub.Local())
	_, srv2 := openOn(t, s2, "srv", th.hub.Local())
	a1, _ := openOn(t, s1, "dev-a", ca.Carrier())
	sendUntil(t, a1, "one", srv1)
	a2, _ := openOn(t, s2, "dev-a", ca.Carrier())
	time.Sleep(200 * time.Millisecond)
	_ = a2.Send("", "two", nil)
	noEnv(t, srv2, "a topic past TopicsPerConn")
}

func TestFrames(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()
	go func() {
		_ = writeFrame(w, framePing, nil)
		_ = writeFrame(w, framePub, []byte("x"))
		_, _ = w.Write([]byte{0, 0, 0, 0}) // a zero-length frame is malformed
	}()
	if typ, body, err := readFrame(r, MaxHubFrame); err != nil || typ != framePing || len(body) != 0 {
		t.Fatalf("%d %q %v", typ, body, err)
	}
	if _, _, err := readFrame(r, 1); !errors.Is(err, errHubFrame) {
		t.Fatalf("oversize frame: %v", err)
	}
	if err := writeFrame(io.Discard, framePub, make([]byte, MaxHubFrame)); err != ErrTooBig {
		t.Fatalf("writing a frame too big: %v", err)
	}
	if _, err := topicBody(string(make([]byte, 256)), nil); err == nil {
		t.Fatal("256-byte topic")
	}
	b, _ := topicBody("t/1", []byte("payload"))
	if topic, p, ok := splitTopicBody(b); !ok || topic != "t/1" || string(p) != "payload" {
		t.Fatalf("split %q %q %v", topic, p, ok)
	}
	if _, _, ok := splitTopicBody([]byte{5, 'a'}); ok {
		t.Fatal("short topic body")
	}
}
