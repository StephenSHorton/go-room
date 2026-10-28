package room

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// The TURN server and its clients run on 127.0.0.1 sockets only.

func newTestTURN(t *testing.T, edit func(*TURNConfig)) (*TURNServer, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := TURNConfig{UDP: pc, RelayIP: netip.MustParseAddr("127.0.0.1"), Logf: t.Logf}
	_, _ = rand.Read(cfg.Key[:])
	if edit != nil {
		edit(&cfg)
	}
	srv, err := NewTURN(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, pc.LocalAddr().String()
}

func quietLogs() logging.LoggerFactory {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	return lf
}

// allocate makes a TURN client on 127.0.0.1 and allocates a relayed socket.
func allocate(t *testing.T, server string, c TURNCreds) (net.PacketConn, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server,
		Username: c.Username, Password: c.Credential, Realm: DefaultTURNRealm,
		Conn: pc, LoggerFactory: quietLogs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close(); _ = pc.Close() })
	if err := cl.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := cl.AllocateWithContext(ctx)
	if err == nil {
		t.Cleanup(func() { _ = relay.Close() })
	}
	return relay, err
}

func readWithin(c net.PacketConn, d time.Duration) (string, bool) {
	buf := make([]byte, 1500)
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

// relayBoth opens permissions both ways and checks a packet from a reaches b.
func relayBoth(a, b net.PacketConn) bool {
	_, _ = b.WriteTo([]byte("open"), a.LocalAddr())
	_, _ = a.WriteTo([]byte("open"), b.LocalAddr())
	for range 5 {
		_, _ = a.WriteTo([]byte("hello"), b.LocalAddr())
		if msg, ok := readWithin(b, 400*time.Millisecond); ok && (msg == "hello" || msg == "open") {
			return true
		}
	}
	return false
}

func TestTURNRelaysBetweenMembers(t *testing.T) {
	var revoked atomic.Bool
	srv, addr := newTestTURN(t, func(c *TURNConfig) {
		c.Authorize = func(user string) error {
			if revoked.Load() && user == "dev-b" {
				return errors.New("revoked")
			}
			return nil
		}
	})
	ca := srv.Issue("dev-a")
	// The username names no stable id, and a later credential's differs.
	if strings.Contains(ca.Username, "dev-a") || ca.TTL < DefaultTURNTTL-time.Minute {
		t.Fatalf("creds %q ttl %v", ca.Username, ca.TTL)
	}
	if _, user, ok := srv.parseUsername(ca.Username); !ok || user != "dev-a" {
		t.Fatalf("parse %q = %q %v", ca.Username, user, ok)
	}
	if later := srv.mint("dev-a", time.Now().Add(time.Hour)); later.Username == ca.Username {
		t.Fatal("two expiries, one username")
	}
	ra, err := allocate(t, addr, ca)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := allocate(t, addr, srv.Issue("dev-b"))
	if err != nil {
		t.Fatal(err)
	}
	if !relayBoth(ra, rb) || !relayBoth(rb, ra) {
		t.Fatal("no relay between two members")
	}

	// A plain socket on loopback isn't a peer the default filter allows.
	plain, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	_, _ = plain.WriteTo([]byte("x"), ra.LocalAddr())
	_, _ = ra.WriteTo([]byte("to loopback"), plain.LocalAddr())
	if msg, ok := readWithin(plain, 300*time.Millisecond); ok {
		t.Fatalf("relayed to loopback: %q", msg)
	}

	// Revoked: the next allocation is refused.
	revoked.Store(true)
	if _, err := allocate(t, addr, srv.Issue("dev-b")); err == nil {
		t.Fatal("revoked device allocated")
	}
	// Expired, forged and malformed credentials.
	old := srv.mint("dev-a", time.Now().Add(-time.Minute))
	if _, err := allocate(t, addr, old); err == nil {
		t.Fatal("expired credentials allocated")
	}
	forged := ca
	forged.Credential = srv.Issue("dev-c").Credential
	if _, err := allocate(t, addr, forged); err == nil {
		t.Fatal("forged credential allocated")
	}
	if _, err := allocate(t, addr, TURNCreds{Username: "dev-a", Credential: "x"}); err == nil {
		t.Fatal("username without expiry allocated")
	}
}

func TestTURNGuestAndCaps(t *testing.T) {
	srv, addr := newTestTURN(t, func(c *TURNConfig) { c.MaxPerUser = 1 })
	rm, err := allocate(t, addr, srv.Issue("dev-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allocate(t, addr, srv.Issue("dev-a")); err == nil {
		t.Fatal("second allocation past MaxPerUser")
	}
	gc := srv.IssueGuest(time.Now().Add(5 * time.Minute))
	if !strings.Contains(gc.Username, ":"+guestUserPrefix) || gc.TTL > 5*time.Minute {
		t.Fatalf("guest creds %q %v", gc.Username, gc.TTL)
	}
	rg, err := allocate(t, addr, gc)
	if err != nil {
		t.Fatal(err)
	}
	// A guest reaches relayed addresses on this server...
	if !relayBoth(rg, rm) {
		t.Fatal("guest couldn't reach a relayed address")
	}
	// ...and nothing else.
	plain, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer plain.Close()
	_, _ = rg.WriteTo([]byte("out"), plain.LocalAddr())
	if _, ok := readWithin(plain, 300*time.Millisecond); ok {
		t.Fatal("guest relayed to a plain socket")
	}
	// A revoked guest can't allocate again; an unknown guest never could.
	_, gu, _ := strings.Cut(gc.Username, ":")
	srv.revokeGuest(gu)
	if _, err := allocate(t, addr, gc); err == nil {
		t.Fatal("revoked guest allocated")
	}
	fake := srv.mint(guestUserPrefix+"nobody", time.Now().Add(time.Minute))
	if _, err := allocate(t, addr, fake); err == nil {
		t.Fatal("unissued guest allocated")
	}
}

// A request with a real username but no valid MESSAGE-INTEGRITY teaches
// the server nothing about its source address.
func TestTURNLearnsSourcesOnlyAfterIntegrity(t *testing.T) {
	srv, addr := newTestTURN(t, nil)
	good := srv.Issue("dev-a")
	for range 3 {
		bad := good
		bad.Credential = "not-the-credential"
		if _, err := allocate(t, addr, bad); err == nil {
			t.Fatal("bad integrity allocated")
		}
	}
	srv.mu.Lock()
	n := len(srv.srcs)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d sources remembered from failed requests", n)
	}
	if _, err := allocate(t, addr, good); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	n = len(srv.srcs)
	srv.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d sources after one verified client", n)
	}
}

// Guests share a small pool, and a revoked guest's allocations close.
func TestTURNGuestPool(t *testing.T) {
	srv, addr := newTestTURN(t, func(c *TURNConfig) { c.MaxGuests = 2 })
	g1 := srv.IssueGuest(time.Now().Add(5 * time.Minute))
	g2 := srv.IssueGuest(time.Now().Add(5 * time.Minute))
	if _, err := allocate(t, addr, g1); err != nil {
		t.Fatal(err)
	}
	if _, err := allocate(t, addr, g2); err != nil {
		t.Fatal(err)
	}
	if _, err := allocate(t, addr, srv.IssueGuest(time.Now().Add(5*time.Minute))); err == nil {
		t.Fatal("a third guest allocation past MaxGuests")
	}
	if _, err := allocate(t, addr, srv.Issue("dev-a")); err != nil {
		t.Fatalf("a member was refused while guests hold their pool: %v", err)
	}
	_, gu, _ := strings.Cut(g1.Username, ":")
	srv.revokeGuest(gu)
	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		n := srv.guestTotal
		srv.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest allocations after a revoke: %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TURN over TCP caps connections per IP and drops ones that go quiet.
func TestTURNTCPCapsAndIdle(t *testing.T) {
	old := turnTCPIdle
	turnTCPIdle = 200 * time.Millisecond
	t.Cleanup(func() { turnTCPIdle = old })
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := TURNConfig{UDP: pc, TCP: ln, RelayIP: netip.MustParseAddr("127.0.0.1"), MaxTCPPerIP: 2}
	_, _ = rand.Read(cfg.Key[:])
	srv, err := NewTURN(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	dial := func() net.Conn {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = c.Write([]byte{0x00})
		return c
	}
	closed := func(c net.Conn, within time.Duration) bool {
		_ = c.SetReadDeadline(time.Now().Add(within))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && !(errors.As(err, &ne) && ne.Timeout())
	}
	a, b := dial(), dial()
	time.Sleep(50 * time.Millisecond)
	if c := dial(); !closed(c, time.Second) {
		t.Fatal("a third connection from one IP stayed open")
	}
	if !closed(a, 2*time.Second) || !closed(b, 2*time.Second) {
		t.Fatal("silent connections stayed open past the idle timeout")
	}
	// Their slots are free again.
	time.Sleep(50 * time.Millisecond)
	if c := dial(); closed(c, 100*time.Millisecond) {
		t.Fatal("a new connection was refused after the others closed")
	}
}

func TestTURNConfigChecks(t *testing.T) {
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer pc.Close()
	for _, cfg := range []TURNConfig{
		{RelayIP: netip.MustParseAddr("127.0.0.1"), Key: [32]byte{1}},
		{UDP: pc, Key: [32]byte{1}},
		{UDP: pc, RelayIP: netip.MustParseAddr("127.0.0.1")},
	} {
		if _, err := NewTURN(cfg); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
}

func TestRelayFetch(t *testing.T) {
	var calls atomic.Int32
	r := NewRelay(RelayConfig{Fetch: func(context.Context) (TURNCreds, error) {
		calls.Add(1)
		return TURNCreds{Username: "1:a", Credential: "c", TTL: time.Hour,
			URIs: []string{"stun:192.0.2.1:24817", "turn:192.0.2.1:24817?transport=udp", "turn:192.0.2.1:24817?transport=tcp"}}, nil
	}}, "a", nil)
	if r.Status().State != RelayPending || len(r.TURN()) != 0 {
		t.Fatal("fetch relay before start")
	}
	r.Start()
	defer r.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for r.Status().State != RelayOK && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := r.TURN()
	if len(got) != 2 || got[0].URLs[0] != "stun:192.0.2.1:24817" || got[0].Username != "" ||
		len(got[1].URLs) != 2 || got[1].Username != "1:a" || got[1].Credential != "c" {
		t.Fatalf("TURN() = %+v", got)
	}
	if len(r.Servers()) != len(DefaultSTUN)+2 {
		t.Fatal("Servers should be DefaultSTUN plus TURN()")
	}
	if calls.Load() != 1 {
		t.Fatalf("fetched %d times", calls.Load())
	}
}
