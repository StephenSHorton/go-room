package room

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// boardHub is a test hub whose app also admits other people's devices for
// shared boards: boardOf names each one's person, and topics is what each
// person may subscribe to. The server's own devices get the mesh topic and
// every board topic.
type boardHub struct {
	*testHub
	mu      sync.Mutex
	boardOf map[string]ed25519.PublicKey // another person's device -> its key
	person  map[string]string            // that device -> its person
	topics  map[string][]string          // person -> board topics
	own     []string                     // topics the server's own devices may use
}

func newBoardHub(t *testing.T, edit func(*HubConfig)) *boardHub {
	t.Helper()
	bh := &boardHub{boardOf: map[string]ed25519.PublicKey{}, person: map[string]string{}, topics: map[string][]string{}}
	bh.testHub = newTestHub(t, func(c *HubConfig) {
		c.AuthorizeBoard = func(id string, pub ed25519.PublicKey) (string, error) {
			bh.mu.Lock()
			defer bh.mu.Unlock()
			if want, ok := bh.boardOf[id]; !ok || !want.Equal(pub) {
				return "", errors.New("not a board member")
			}
			return bh.person[id], nil
		}
		c.AllowTopic = func(p HubPeer, topic string) bool {
			bh.mu.Lock()
			defer bh.mu.Unlock()
			list := bh.own
			if p.Person != "" {
				list = bh.topics[p.Person]
			}
			for _, x := range list {
				if x == topic {
					return true
				}
			}
			return false
		}
		if edit != nil {
			edit(c)
		}
	})
	return bh
}

// visitor dials as another person's device, a member of person's boards.
func (bh *boardHub) visitor(t *testing.T, id, person string, edit func(*HubDialConfig)) *HubClient {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	bh.mu.Lock()
	bh.boardOf[id], bh.person[id] = pub, person
	bh.mu.Unlock()
	return bh.dialAs(t, id, key, edit)
}

func (bh *boardHub) peer(id string) (HubPeer, *hubConn) {
	bh.hub.mu.Lock()
	defer bh.hub.mu.Unlock()
	for c := range bh.hub.conns {
		if c.peer.ID == id {
			return c.peer, c
		}
	}
	return HubPeer{}, nil
}

func (bh *boardHub) subscribed(id, topic string) bool {
	_, c := bh.peer(id)
	if c == nil {
		return false
	}
	bh.hub.mu.Lock()
	defer bh.hub.mu.Unlock()
	return c.subs[topic]
}

// Another person's device is admitted as a board peer: it reaches the board
// topic and meets the server's own device there, but never the mesh topic,
// even with the mesh secret; it can't open guest topics; and Recheck takes
// a board away once the app's state no longer grants it.
func TestHubBoardPeers(t *testing.T) {
	fastHubRetry(t)
	mesh, board := testSecret(t), testSecret(t)
	bh := newBoardHub(t, nil)
	bh.own = []string{mesh.Topic, board.Topic}
	bh.topics["blake"] = []string{board.Topic}

	a1, _ := bh.member(t, "dev-a1")
	a2, _ := bh.member(t, "dev-a2")
	b1 := bh.visitor(t, "dev-b1", "blake", nil)
	waitFor(t, "all connected", func() bool { return a1.Up() && a2.Up() && b1.Up() })
	if p, _ := bh.peer("dev-b1"); p.Person != "blake" {
		t.Fatalf("board peer %+v", p)
	}
	if p, _ := bh.peer("dev-a1"); p.Person != "" {
		t.Fatalf("own device marked as a board peer: %+v", p)
	}

	// A stranger (neither own nor a board member) is refused.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	stranger := bh.dialAs(t, "dev-x", key, nil)
	time.Sleep(300 * time.Millisecond)
	if stranger.Up() {
		t.Fatal("a stranger was admitted")
	}

	open := func(c *HubClient, id string, s Secret) *node {
		sig, err := Open(s, id, SignalOptions{}, c.Carrier())
		if err != nil {
			t.Fatal(err)
		}
		return newNodeOn(t, sig, id, nodeOpts{})
	}
	// dev-a1 runs two meshes in one process: its own and the board's.
	a1Mesh, a1Board := open(a1, "dev-a1", mesh), open(a1, "dev-a1", board)
	a2Mesh := open(a2, "dev-a2", mesh)
	b1Board := open(b1, "dev-b1", board)
	b1Mesh := open(b1, "dev-b1", mesh) // it has the mesh secret, but the hub won't carry it

	connect := func(a, b *node) {
		go func() {
			for range 50 {
				if b.mesh.Peer(a.id) != nil {
					return
				}
				b.mesh.Connect(a.id)
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	connect(a1Board, b1Board)
	connect(a1Mesh, a2Mesh)
	connect(a1Mesh, b1Mesh)
	pb := waitUp(t, b1Board)
	if pb.ID() != "dev-a1" {
		t.Fatalf("board peer met %s", pb.ID())
	}
	if p := waitUp(t, a1Board); p.ID() != "dev-b1" {
		t.Fatalf("a1's board mesh met %s", p.ID())
	}
	waitUp(t, a2Mesh)
	if p := waitUp(t, a1Mesh); p.ID() != "dev-a2" {
		t.Fatalf("a1's own mesh met %s", p.ID())
	}
	select {
	case p := <-b1Mesh.up:
		t.Fatalf("the board peer reached the mesh topic: met %s", p.ID())
	case <-time.After(2 * time.Second):
	}
	if bh.subscribed("dev-b1", mesh.Topic) || !bh.subscribed("dev-b1", board.Topic) {
		t.Fatal("board peer's subscriptions are wrong")
	}

	// It can't open a guest topic, and an open pairing topic isn't its.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = b1.OpenGuest(ctx, "pair-topic", time.Minute)
	if err := bh.hub.OpenGuest("srv-pairing", time.Minute); err != nil {
		t.Fatal(err)
	}
	b1Pair, _ := openOn(t, testSecret(t), "dev-b1", b1.Carrier())
	_ = b1Pair
	time.Sleep(300 * time.Millisecond)
	bh.hub.mu.Lock()
	_, opened := bh.hub.guests["pair-topic"]
	bh.hub.mu.Unlock()
	if opened {
		t.Fatal("a board peer opened a guest topic")
	}
	if _, c := bh.peer("dev-b1"); c != nil {
		bh.hub.mu.Lock()
		got := bh.hub.allowedLocked(c, "srv-pairing")
		bh.hub.mu.Unlock()
		if got {
			t.Fatal("a board peer may use an open pairing topic")
		}
	}

	// Blake leaves the board: Recheck ends the subscription at once.
	bh.mu.Lock()
	bh.topics["blake"] = nil
	bh.mu.Unlock()
	bh.hub.Recheck()
	if bh.subscribed("dev-b1", board.Topic) {
		t.Fatal("Recheck left a board the app no longer grants")
	}
	// And back: a topic it still wants is granted again.
	bh.mu.Lock()
	bh.topics["blake"] = []string{board.Topic}
	bh.mu.Unlock()
	bh.hub.Recheck()
	if !bh.subscribed("dev-b1", board.Topic) {
		t.Fatal("Recheck didn't grant a wanted topic again")
	}
}

// Board peers have their own connection cap, so they never take the own
// devices' slots.
func TestHubBoardPeerCap(t *testing.T) {
	fastHubRetry(t)
	bh := newBoardHub(t, func(c *HubConfig) { c.Limits.BoardPeers = 1; c.Limits.Members = 1 })
	b1 := bh.visitor(t, "dev-b1", "blake", nil)
	waitFor(t, "b1 up", b1.Up)
	b2 := bh.visitor(t, "dev-b2", "blake", nil)
	a1, _ := bh.member(t, "dev-a1")
	waitFor(t, "own device up beside a board peer", a1.Up)
	time.Sleep(300 * time.Millisecond)
	if b2.Up() {
		t.Fatal("a second board peer got past BoardPeers = 1")
	}
}

// A board peer's TURN credentials are its person's, and they relay only to
// this server's relayed addresses: never to the LAN, even when the app's
// AllowPeer would let a member there, and at most MaxBoardPerUser at once.
func TestTURNBoardUsersAreNarrow(t *testing.T) {
	srv, addr := newTestTURN(t, func(c *TURNConfig) {
		c.MaxBoardPerUser = 1
		c.AllowPeer = func(string, netip.Addr) bool { return true } // the app is generous
	})
	lan := netip.MustParseAddr("10.1.2.3")
	if !srv.allowPeer("dev-a1", lan, 0) {
		t.Fatal("the app's AllowPeer no longer decides for members")
	}
	if srv.allowPeer(boardUserPrefix+"blake", lan, 0) {
		t.Fatal("a board user may relay to the LAN")
	}
	if !srv.allowPeer(boardUserPrefix+"blake", srv.cfg.RelayIP, 0) {
		t.Fatal("a board user may not reach the server's relayed addresses")
	}
	// The default filter, with no AllowPeer: same for board users.
	def, _ := newTestTURN(t, nil)
	def.subnets = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if !def.allowPeer("dev-a1", lan, 0) || def.allowPeer(boardUserPrefix+"blake", lan, 0) || def.allowPeer(guestUserPrefix+"x", lan, 0) {
		t.Fatal("default filter: member to LAN yes, board and guest users no")
	}

	creds := srv.IssueBoard("blake")
	if _, user, ok := srv.parseUsername(creds.Username); !ok || user != boardUserPrefix+"blake" || strings.Contains(creds.Username, "blake") {
		t.Fatalf("board credentials %q read as %q", creds.Username, user)
	}
	if _, err := allocate(t, addr, creds); err != nil {
		t.Fatalf("first board allocation: %v", err)
	}
	if _, err := allocate(t, addr, srv.IssueBoard("blake")); err == nil {
		t.Fatal("a second allocation for the same person got past MaxBoardPerUser = 1")
	}
	if _, err := allocate(t, addr, srv.IssueBoard("carol")); err != nil {
		t.Fatalf("another person's allocation: %v", err)
	}
}

// The hub hands a board peer its person's narrow credentials.
func TestHubBoardPeerTURN(t *testing.T) {
	fastHubRetry(t)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcfg := TURNConfig{UDP: udp, RelayIP: netip.MustParseAddr("127.0.0.1")}
	_, _ = rand.Read(tcfg.Key[:])
	ts, err := NewTURN(tcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ts.Close)
	bh := newBoardHub(t, func(c *HubConfig) { c.TURN = ts })
	b1 := bh.visitor(t, "dev-b1", "blake", nil)
	a1, _ := bh.member(t, "dev-a1")
	waitFor(t, "connected", func() bool { return a1.Up() && b1.Up() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bc, err := b1.TURN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := a1.TURN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, u, _ := ts.parseUsername(bc.Username); u != boardUserPrefix+"blake" {
		t.Fatalf("board peer's TURN user %q", u)
	}
	if _, u, _ := ts.parseUsername(ac.Username); u != "dev-a1" {
		t.Fatalf("own device's TURN user %q", u)
	}
}

// Invite guest topics live up to an hour and have their own allowance, two
// per member beside the two pairing ones; pairing topics stay capped at
// ten minutes.
func TestHubInviteGuests(t *testing.T) {
	fastHubRetry(t)
	th := newTestHub(t, nil)
	c, _ := th.member(t, "dev-a1")
	waitFor(t, "connected", c.Up)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func(topic string, ttl time.Duration, invite bool) {
		t.Helper()
		var err error
		if invite {
			err = c.OpenInvite(ctx, topic, ttl)
		} else {
			err = c.OpenGuest(ctx, topic, ttl)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	left := func(topic string) (time.Duration, bool) {
		th.hub.mu.Lock()
		defer th.hub.mu.Unlock()
		g := th.hub.guests[topic]
		if g == nil {
			return 0, false
		}
		return time.Until(g.expires), g.invite
	}
	open("invite-1", 59*time.Minute, true)
	open("invite-2", 2*time.Hour, true)
	open("pair-1", 30*time.Minute, false)
	open("pair-2", time.Minute, false)
	waitFor(t, "four guest topics", func() bool {
		th.hub.mu.Lock()
		defer th.hub.mu.Unlock()
		return th.hub.guests["pair-2"] != nil
	})
	if d, inv := left("invite-1"); !inv || d < 58*time.Minute || d > 59*time.Minute {
		t.Fatalf("invite-1: %v invite=%v", d, inv)
	}
	if d, _ := left("invite-2"); d > MaxInviteTTL || d < MaxInviteTTL-time.Minute {
		t.Fatalf("invite-2 not capped at an hour: %v", d)
	}
	if d, inv := left("pair-1"); inv || d > MaxGuestTTL {
		t.Fatalf("pair-1: %v invite=%v", d, inv)
	}
	// A third of either kind is refused.
	if err := th.hub.openGuest("invite-3", time.Minute, "dev-a1", true); err == nil {
		t.Fatal("a third invite topic opened")
	}
	if err := th.hub.openGuest("pair-3", time.Minute, "dev-a1", false); err == nil {
		t.Fatal("a third pairing topic opened")
	}
	// A guest with the invite topic gets in; closing it drops the guest.
	g := th.guest(t, "invite-1")
	waitFor(t, "invite guest up", g.Up)
	c.CloseGuest("invite-1")
	waitFor(t, "invite guest dropped", func() bool { return !g.Up() })
	// The server's own invite window too.
	if err := th.hub.OpenInvite("srv-invite", 3*time.Hour); err != nil {
		t.Fatal(err)
	}
	if d, inv := left("srv-invite"); !inv || d > MaxInviteTTL {
		t.Fatalf("server's invite: %v invite=%v", d, inv)
	}
}
