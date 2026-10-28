package room

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// within fails the test if fn doesn't return in d.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s didn't return within %v", what, d)
	}
}

// blockedWriter opens a stream and writes into it until Write blocks on a
// receiver that never reads. The returned channel gets Write's error.
func blockedWriter(t *testing.T, ctx context.Context, pa *Peer, label string, write func(*Stream, []byte) error) (*Stream, chan error) {
	t.Helper()
	st, err := pa.OpenStream(ctx, label)
	if err != nil {
		t.Fatal(err)
	}
	werr := make(chan error, 1)
	go func() { werr <- write(st, make([]byte, 64<<20)) }()
	deadline := time.Now().Add(20 * time.Second)
	for st.dc.BufferedAmount() <= highWater {
		select {
		case err := <-werr:
			t.Fatalf("%s: write ended before blocking: %v", label, err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: write never backed up", label)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // into flow.wait
	return st, werr
}

func writeAll(st *Stream, p []byte) error { _, err := st.Write(p); return err }

// A Write blocked on a receiver that never reads must not hang Stream.Close,
// Peer.Close or Mesh.Close.
func TestStreamCloseUnblocksWriter(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{})
	b := newNode(t, hub, s, "dev-b", nodeOpts{})
	pa, pb := pair(t, a, b)
	hold := make(chan struct{})
	defer close(hold)
	pb.OnStream(func(_ string, st *Stream) { <-hold }) // never reads
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Stream.Close from another goroutine stops the Write and returns
	// without the 30 s flush.
	st, werr := blockedWriter(t, ctx, pa, "blob/1", writeAll)
	within(t, 3*time.Second, "Stream.Close", func() { _ = st.Close() })
	if err := <-werr; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked write after Close: %v", err)
	}
	if _, err := st.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}

	// 2. WriteContext gives up when its ctx ends; the stream stays usable.
	wctx, wcancel := context.WithCancel(ctx)
	st2, werr2 := blockedWriter(t, ctx, pa, "blob/2", func(st *Stream, p []byte) error {
		_, err := st.WriteContext(wctx, p)
		return err
	})
	wcancel()
	select {
	case err := <-werr2:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled write: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled WriteContext didn't return")
	}

	// 3. Peer.Close with a Write blocked on that stream.
	go func() { _, _ = st2.Write(make([]byte, 8<<20)) }()
	time.Sleep(200 * time.Millisecond)
	_, werr3 := blockedWriter(t, ctx, pa, "blob/3", writeAll)
	within(t, 3*time.Second, "Peer.Close", func() { pa.Close("test") })
	if err := <-werr3; err == nil {
		t.Fatal("blocked write survived Peer.Close")
	}
	waitDown(t, a)
	waitDown(t, b)

	// 4. Mesh.Close with a Write blocked on a fresh connection.
	pa2, pb2 := pair(t, a, b)
	pb2.OnStream(func(_ string, st *Stream) { <-hold })
	_, werr4 := blockedWriter(t, ctx, pa2, "blob/4", writeAll)
	within(t, 5*time.Second, "Mesh.Close", a.mesh.Close)
	if err := <-werr4; err == nil {
		t.Fatal("blocked write survived Mesh.Close")
	}
}

// forger holds the room key and seals envelopes under any From it likes, as
// a revoked device on an old topic or a pairing-code holder could.
type forger struct {
	hub *MemHub
	s   Secret
}

func (f forger) send(t *testing.T, from, to, typ string, body any, at time.Time) {
	t.Helper()
	c, err := newCore(f.s, from, SignalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return at }
	payload, err := c.seal(to, typ, body)
	if err != nil {
		t.Fatal(err)
	}
	f.hub.Publish(f.s.Topic, payload)
}

// throwawayOffer is a real SDP offer from a PeerConnection that will never
// finish a handshake, on loopback only.
func throwawayOffer(t *testing.T) string {
	t.Helper()
	se := webrtc.SettingEngine{}
	LoopbackOnly()(&se)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, err := pc.CreateDataChannel("x", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	return pc.LocalDescription().SDP
}

// Someone with the room key, but not a device key, can't take down an up,
// authenticated connection with rtc.* envelopes.
func TestMeshForgedEnvelopes(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{})
	b := newNode(t, hub, s, "dev-b", nodeOpts{})
	pa, pb := pair(t, a, b)
	f := forger{hub, s}
	now := time.Now()

	// An offer older (on the offerer's clock) than the live session's: a
	// replay a broker held back. Ignored outright.
	f.send(t, a.id, b.id, MsgOffer, sdpBody{Session: "s-old", SDP: throwawayOffer(t)}, now.Add(-60*time.Second))
	// A newer offer with a real SDP: answered beside the live connection,
	// which stays until the new one passes the handshake (it never will).
	f.send(t, a.id, b.id, MsgOffer, sdpBody{Session: "s-forged", SDP: throwawayOffer(t)}, now.Add(time.Second))
	// A newer offer with junk SDP.
	f.send(t, a.id, b.id, MsgOffer, sdpBody{Session: "s-junk", SDP: "v=0"}, now.Add(2*time.Second))
	// A want to the offerer while its connection is healthy.
	f.send(t, b.id, a.id, MsgWant, struct{}{}, now)
	// Byes naming the live session (any key holder can read it), without the
	// token from inside DTLS.
	f.send(t, a.id, b.id, MsgBye, byeBody{Session: pb.Session(), Reason: "forged"}, now)
	f.send(t, b.id, a.id, MsgBye, byeBody{Session: pa.Session(), Token: "guess", Reason: "forged"}, now)
	// An answer for the live session.
	f.send(t, b.id, a.id, MsgAnswer, sdpBody{Session: pa.Session(), SDP: "v=0"}, now)

	deadline := time.After(4 * time.Second)
wait:
	for {
		select {
		case err := <-a.down:
			t.Fatalf("a went down: %v", err)
		case err := <-b.down:
			t.Fatalf("b went down: %v", err)
		case p := <-a.up:
			t.Fatalf("a: %s came up again", p.ID())
		case p := <-b.up:
			t.Fatalf("b: %s came up again", p.ID())
		case <-deadline:
			break wait
		}
	}
	if a.mesh.Peer(b.id) != pa || b.mesh.Peer(a.id) != pb {
		t.Fatal("the live peers were replaced")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exchange(t, ctx, pa, pb)

	// A real bye (with the token) still ends it.
	pa.Close("done")
	var bye *ByeError
	if err := waitDown(t, b); !errors.As(err, &bye) || bye.Reason != "done" {
		t.Fatalf("b down: %v", err)
	}
}

// When the offerer re-offers while the answerer still has the old
// connection up, the new one is made before the old one is broken: the
// answerer sees the old peer down (replaced) and then the new one up.
func TestMeshReplaceMakeBeforeBreak(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{})
	b := newNode(t, hub, s, "dev-b", nodeOpts{})
	pa, pb := pair(t, a, b)

	// a loses track of its connection without closing it (as after a crash
	// the other side hasn't noticed yet), then connects again.
	a.mesh.mu.Lock()
	delete(a.mesh.peers, b.id)
	a.mesh.mu.Unlock()
	a.mesh.Connect(b.id)

	if err := waitDown(t, b); !errors.Is(err, ErrReplaced) {
		t.Fatalf("b's old peer: %v", err)
	}
	pb2 := waitUp(t, b)
	pa2 := waitUp(t, a)
	if pb2.Session() == pb.Session() || pa2.Session() != pb2.Session() {
		t.Fatal("sessions")
	}
	if b.mesh.Peer(a.id) != pb2 {
		t.Fatal("b's mesh still points at the old peer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exchange(t, ctx, pa2, pb2)
	// The orphaned old connection on a goes down once b closed its side.
	waitDown(t, a)
	select {
	case <-pa.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("a's orphaned peer stayed up")
	}
}

// A fetcher that closes one stream and opens the next at once must not find
// the receiver still counting the old one against the cap.
func TestMeshStreamCapOverlap(t *testing.T) {
	hub := NewMemHub()
	s := testSecret(t)
	a := newNode(t, hub, s, "dev-a", nodeOpts{streams: 1})
	b := newNode(t, hub, s, "dev-b", nodeOpts{streams: 1})
	pa, pb := pair(t, a, b)

	got := make(chan int, 8)
	var arrived, closed [5]chan struct{}
	for i := range arrived {
		arrived[i] = make(chan struct{})
		closed[i] = make(chan struct{})
	}
	pb.OnStream(func(label string, st *Stream) {
		i := int(label[len(label)-1] - 'a')
		close(arrived[i])
		data, _ := io.ReadAll(st)
		got <- len(data)
		// Still unwinding when the next stream arrives.
		select {
		case <-arrived[i+1]:
		case <-time.After(2 * time.Second):
		}
		_ = st.Close()
		close(closed[i])
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := range 4 {
		if i >= 2 {
			<-closed[i-2] // one overlap at a time, as a fetcher has it
		}
		st, err := pa.OpenStream(ctx, "blob/"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		select {
		case n := <-got:
			if n != 1000 {
				t.Fatalf("stream %d: %d bytes", i, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("stream %d never reached the handler", i)
		}
	}
}
