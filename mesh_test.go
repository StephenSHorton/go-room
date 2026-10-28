package room

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// node is one member in a test: its signaler, mesh and what happened.
type node struct {
	id   string
	key  ed25519.PrivateKey
	sig  Signaler
	mesh *Mesh
	up   chan *Peer
	down chan error
}

type nodeOpts struct {
	accept  func(peer string, pub ed25519.PublicKey) error
	sign    func([]byte) []byte // override (a forger)
	streams int
	allow   func(peer string) bool
}

// newNode opens a member on hub that connects over 127.0.0.1 only: no STUN,
// loopback candidates, no mDNS. Nothing in these tests binds a LAN address
// or talks to a public broker.
func newNode(t *testing.T, hub *MemHub, s Secret, id string, o nodeOpts) *node {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	n := &node{id: id, key: key, up: make(chan *Peer, 8), down: make(chan error, 8)}
	n.sig = hub.Open(s, id, SignalOptions{})
	ident := KeyIdentity(key)
	if o.sign != nil {
		ident.Sign = o.sign
	}
	accept := o.accept
	if accept == nil {
		accept = func(string, ed25519.PublicKey) error { return nil }
	}
	m, err := NewMesh(n.sig, Config{
		Self:       id,
		Identity:   ident,
		Accept:     accept,
		Allow:      o.allow,
		ICE:        func() []ICEServer { return nil },
		Tune:       LoopbackOnly(),
		MaxMessage: 8 << 20,
		MaxStreams: o.streams,
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	n.mesh = m
	m.OnPeer(func(p *Peer) { n.up <- p })
	m.OnPeerDown(func(_ string, err error) { n.down <- err })
	t.Cleanup(func() {
		m.Close()
		n.sig.Close()
	})
	return n
}

func waitUp(t *testing.T, n *node) *Peer {
	t.Helper()
	select {
	case p := <-n.up:
		return p
	case <-time.After(20 * time.Second):
		t.Fatalf("%s: no peer came up", n.id)
		return nil
	}
}

func waitDown(t *testing.T, n *node) error {
	t.Helper()
	select {
	case err := <-n.down:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: peer didn't go down", n.id)
		return nil
	}
}

// requireLoopback fails if an SDP offers any non-loopback candidate.
func requireLoopback(t *testing.T, label, sdp string) {
	t.Helper()
	n := 0
	for _, line := range strings.Split(sdp, "\n") {
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			t.Fatalf("%s: bad candidate %q", label, line)
		}
		if ip := net.ParseIP(f[4]); ip == nil || !ip.IsLoopback() {
			t.Fatalf("%s: non-loopback candidate %q", label, strings.TrimSpace(line))
		}
		n++
	}
	if n == 0 {
		t.Fatalf("%s: no candidates", label)
	}
}

func pair(t *testing.T, a, b *node) (pa, pb *Peer) {
	t.Helper()
	// The higher id asks; the lower one offers.
	b.mesh.Connect(a.id)
	pb = waitUp(t, b)
	pa = waitUp(t, a)
	return pa, pb
}

func TestMeshEndToEnd(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{})
	b := newNode(t, hub, s, "dev-b", nodeOpts{})
	pa, pb := pair(t, a, b)

	// Each side proved the key it holds, and both see the same DTLS pair.
	if pa.ID() != b.id || pb.ID() != a.id {
		t.Fatalf("ids %q %q", pa.ID(), pb.ID())
	}
	if !pa.Pub().Equal(b.key.Public()) || !pb.Pub().Equal(a.key.Public()) {
		t.Fatal("wrong peer keys")
	}
	la, ra := pa.Fingerprints()
	lb, rb := pb.Fingerprints()
	if la == "" || ra == "" || la != rb || ra != lb || la == ra {
		t.Fatalf("fingerprints a=(%s, %s) b=(%s, %s)", la, ra, lb, rb)
	}
	if pa.Path() != "direct" || pa.Session() != pb.Session() {
		t.Fatalf("path %q sessions %q %q", pa.Path(), pa.Session(), pb.Session())
	}
	requireLoopback(t, "a", pa.pc.LocalDescription().SDP)
	requireLoopback(t, "b", pb.pc.LocalDescription().SDP)
	if a.mesh.Peer(b.id) != pa || len(b.mesh.Peers()) != 1 {
		t.Fatal("mesh lookups")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Messages both ways, small, empty and big (many 16 KiB pieces).
	big := make([]byte, 3<<20+5)
	_, _ = rand.Read(big)
	for _, msg := range [][]byte{[]byte("hello"), {}, big} {
		if err := pa.Messages().Send(ctx, msg); err != nil {
			t.Fatal(err)
		}
		got, err := pb.Messages().Recv(ctx)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("b got %d bytes (%v), want %d", len(got), err, len(msg))
		}
		if err := pb.Messages().Send(ctx, msg); err != nil {
			t.Fatal(err)
		}
		if got, err := pa.Messages().Recv(ctx); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("a got %d bytes (%v), want %d", len(got), err, len(msg))
		}
	}
	if err := pa.Messages().Send(ctx, make([]byte, 8<<20+1)); !errors.Is(err, ErrTooBig) {
		t.Fatalf("oversized send: %v", err)
	}

	// A stream: many MB written and closed at once arrive whole.
	type result struct {
		label string
		sum   [32]byte
		n     int
		err   error
	}
	got := make(chan result, 1)
	pb.OnStream(func(label string, st *Stream) {
		data, err := io.ReadAll(st)
		_ = st.Close()
		got <- result{label, sha256.Sum256(data), len(data), err}
	})
	blob := make([]byte, 6<<20+123)
	_, _ = rand.Read(blob)
	st, err := pa.OpenStream(ctx, "blob/1")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.Write(blob); err != nil || n != len(blob) {
		t.Fatalf("write %d %v", n, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.err != nil || r.label != "blob/1" || r.n != len(blob) || r.sum != sha256.Sum256(blob) {
			t.Fatalf("stream: label %q, %d bytes of %d, err %v, hash match %v", r.label, r.n, len(blob), r.err, r.sum == sha256.Sum256(blob))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("stream didn't arrive")
	}
	if _, err := pa.OpenStream(ctx, SyncLabel); err == nil {
		t.Fatal("opened a stream named sync")
	}

	// Reconnect 1: a closes on purpose. Both see it; asking again works.
	pa.Close("test")
	var bye *ByeError
	if err := waitDown(t, b); !errors.As(err, &bye) || bye.Reason != "test" {
		t.Fatalf("b down: %v", err)
	}
	var local *LocalCloseError
	if err := waitDown(t, a); !errors.As(err, &local) {
		t.Fatalf("a down: %v", err)
	}
	if _, err := pa.Messages().Recv(ctx); err == nil {
		t.Fatal("recv on a closed peer")
	}
	pa2, pb2 := pair(t, a, b)
	if pa2.Session() == pa.Session() {
		t.Fatal("reconnect reused the session")
	}
	exchange(t, ctx, pa2, pb2)

	// Reconnect 2: the connection dies with no bye (as when a machine
	// vanishes). Both sides notice; the offerer's Connect brings it back.
	_ = pa2.pc.Close()
	waitDown(t, a)
	waitDown(t, b)
	a.mesh.Connect(b.id)
	pa3 := waitUp(t, a)
	pb3 := waitUp(t, b)
	exchange(t, ctx, pa3, pb3)
}

func exchange(t *testing.T, ctx context.Context, x, y *Peer) {
	t.Helper()
	if err := x.Messages().Send(ctx, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if m, err := y.Messages().Recv(ctx); err != nil || string(m) != "ping" {
		t.Fatalf("recv %q %v", m, err)
	}
	if err := y.Messages().Send(ctx, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	if m, err := x.Messages().Recv(ctx); err != nil || string(m) != "pong" {
		t.Fatalf("recv %q %v", m, err)
	}
}

func TestMeshStreamLimit(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{streams: 2})
	b := newNode(t, hub, s, "dev-b", nodeOpts{streams: 2})
	pa, pb := pair(t, a, b)
	pb.OnStream(func(string, *Stream) {}) // keep them open
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s1, err := pa.OpenStream(ctx, "blob/1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pa.OpenStream(ctx, "blob/2"); err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelShort()
	if _, err := pa.OpenStream(short, "blob/3"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("third stream past the cap: %v", err)
	}
	// Closing one frees a slot.
	_ = s1.Close()
	if _, err := pa.OpenStream(ctx, "blob/4"); err != nil {
		t.Fatal(err)
	}
}

func TestMeshRefusesAndForgers(t *testing.T) {
	t.Run("accept refuses", func(t *testing.T) {
		hub := NewMemHub()
		s := testSecret(t)
		a := newNode(t, hub, s, "dev-a", nodeOpts{})
		b := newNode(t, hub, s, "dev-b", nodeOpts{accept: func(string, ed25519.PublicKey) error { return errors.New("not certified") }})
		b.mesh.Connect(a.id)
		expectNoPeer(t, a, b)
	})
	t.Run("forged signature", func(t *testing.T) {
		hub := NewMemHub()
		s := testSecret(t)
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		a := newNode(t, hub, s, "dev-a", nodeOpts{})
		// b claims its own public key but signs with another key.
		b := newNode(t, hub, s, "dev-b", nodeOpts{sign: func(m []byte) []byte { return ed25519.Sign(other, m) }})
		b.mesh.Connect(a.id)
		expectNoPeer(t, a, b)
	})
	t.Run("not allowed", func(t *testing.T) {
		hub := NewMemHub()
		s := testSecret(t)
		a := newNode(t, hub, s, "dev-a", nodeOpts{allow: func(string) bool { return false }})
		b := newNode(t, hub, s, "dev-b", nodeOpts{})
		b.mesh.Connect(a.id)
		expectNoPeer(t, a, b)
	})
}

func expectNoPeer(t *testing.T, ns ...*node) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case p := <-ns[0].up:
			t.Fatalf("%s: %s came up", ns[0].id, p.ID())
		case p := <-ns[1].up:
			t.Fatalf("%s: %s came up", ns[1].id, p.ID())
		case <-deadline:
			return
		}
	}
}
