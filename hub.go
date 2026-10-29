package room

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// The hub is the signaling server a home server runs: devices connect to it
// over TLS, prove their device key over the TLS session, and subscribe to
// the topics they may use. It routes sealed payloads by topic and keeps
// nothing: no retained messages, no log of envelopes. It is not an open
// relay: members must pass the app's Authorize, may subscribe only to the
// topics the app allows (by default the topics the server's own rooms have
// open) and to open guest topics, and guests reach only the one pairing
// topic a member opened for them.
//
// A board peer is another person's device, admitted by AuthorizeBoard when
// Authorize refuses it (a shared board's member). It may subscribe only to
// the topics AllowTopic grants it (nothing when AllowTopic is nil), never to
// a guest topic, can't open guest topics, and gets narrow TURN credentials
// that relay only to this server's own relayed addresses.

// MaxGuestTTL caps how long a pairing guest topic stays open.
const MaxGuestTTL = 10 * time.Minute

// MaxInviteTTL caps how long an invite guest topic stays open: long enough
// for a voice call.
const MaxInviteTTL = time.Hour

// HubPeer is one connected client as the hub sees it.
type HubPeer struct {
	ID     string // the member's device id ("" for a guest)
	Pub    ed25519.PublicKey
	Guest  bool
	Remote netip.AddrPort
	// Person is set on a board peer: the person (as AuthorizeBoard named
	// it) whose device this is. "" for the server's own devices and guests.
	Person string
}

// HubLimits bound what a hub on someone's desktop will take. Zero values
// are the defaults in brackets.
type HubLimits struct {
	Members          int           // member connections [64]
	Guests           int           // guest connections [8]
	HandshakesPerIP  int           // handshakes in flight per remote IP (an IPv6 /64 is one) [4]
	Handshakes       int           // handshakes in flight in total [64]
	TopicsPerConn    int           // subscriptions per connection [8]
	GuestsPerMember  int           // pairing guest topics one member may have open [2]
	InvitesPerMember int           // invite guest topics one member may have open, beside those [2]
	BoardPeers       int           // board peer connections [32]
	PubRate          float64       // pub frames per second per connection [50]
	PubBurst         float64       // [100]
	FailBackoff      time.Duration // refuse an IP this long after a failed handshake, doubling to 30 s [1 s]; negative: off
}

func (l HubLimits) withDefaults() HubLimits {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.Members, 64)
	def(&l.Guests, 8)
	def(&l.HandshakesPerIP, 4)
	def(&l.Handshakes, 64)
	def(&l.TopicsPerConn, 8)
	def(&l.GuestsPerMember, 2)
	def(&l.InvitesPerMember, 2)
	def(&l.BoardPeers, 32)
	if l.PubRate <= 0 {
		l.PubRate = 50
	}
	if l.PubBurst <= 0 {
		l.PubBurst = 100
	}
	if l.FailBackoff == 0 {
		l.FailBackoff = time.Second
	}
	return l
}

// HubConfig sets up a hub.
type HubConfig struct {
	// Self is the server device's id; Identity signs its welcome.
	Self     string
	Identity Identity
	// Authorize decides on a member that proved it holds pub's private key;
	// nil error admits it. Required.
	Authorize func(id string, pub ed25519.PublicKey) error
	// AuthorizeBoard, when set, is asked about a device Authorize refused:
	// another person's device that is a member of a board this server
	// serves. It returns the person the device belongs to (a nil error
	// admits it as a board peer, HubPeer.Person set). It runs outside the
	// hub's lock.
	AuthorizeBoard func(id string, pub ed25519.PublicKey) (person string, err error)
	// AllowTopic decides a member's subscriptions other than open guest
	// topics, and every subscription of a board peer (c.Person set). nil:
	// a member gets only topics the server's own rooms (Local) have open,
	// and a board peer gets nothing. It runs with the hub's lock held:
	// answer from the app's own state and don't call back into the hub.
	// After the state it reads changes, call Recheck.
	AllowTopic func(c HubPeer, topic string) bool
	// TURN, when set, answers turn.get: members get Issue(id), guests
	// IssueGuest until their topic closes.
	TURN *TURNServer
	// PublicUDP, when set, is the public address of TURN's UDP port as the
	// router mapped it; it rides in turn.creds so a device that dialed the
	// public TCP address finds UDP when the router gave it another port.
	PublicUDP func() netip.AddrPort
	// Bridge, when set, carries open guest topics between this LAN and the
	// hub both ways, so a device at home with only a pairing code reaches a
	// member away from home.
	Bridge *LAN
	// Limits; the zero value is the defaults.
	Limits HubLimits
	// Logf, when set, gets diagnostics (never payloads or credentials).
	Logf func(format string, args ...any)
}

// Hub is a running signaling hub.
type Hub struct {
	cfg    HubConfig
	lim    HubLimits
	tlsCfg *tls.Config
	now    func() time.Time

	mu        sync.Mutex
	conns     map[*hubConn]bool
	topics    map[string]*hubTopic
	guests    map[string]*guestTopic
	inflight  map[netip.Addr]int // by limitKey
	nInflight int
	fails     map[netip.Addr]*hubFail // by limitKey
	pending   map[net.Conn]bool       // connections still in their handshake
	listeners []net.Listener
	closed    bool
	wg        sync.WaitGroup
}

type hubTopic struct {
	remote map[*hubConn]bool
	local  []*hubLocalLeg
}

type guestTopic struct {
	owner   string // the member that opened it ("" = the server itself)
	invite  bool   // an invite window (MaxInviteTTL), else a pairing one
	expires time.Time
	timer   *time.Timer
	bridge  Leg
	orphan  *time.Timer // the owner's last connection dropped: closes it after hubGuestGrace
}

type hubFail struct {
	until   time.Time
	backoff time.Duration
}

// NewHub makes a hub; Serve starts taking connections.
func NewHub(cfg HubConfig) (*Hub, error) {
	if cfg.Self == "" || len(cfg.Self) > 255 {
		return nil, errors.New("room: hub needs a Self id of 1-255 bytes")
	}
	if len(cfg.Identity.Pub) != ed25519.PublicKeySize || cfg.Identity.Sign == nil {
		return nil, errors.New("room: hub needs an ed25519 Identity")
	}
	if cfg.Authorize == nil {
		return nil, errors.New("room: HubConfig.Authorize is required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	cert, err := hubCert()
	if err != nil {
		return nil, err
	}
	return &Hub{
		cfg: cfg,
		lim: cfg.Limits.withDefaults(),
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{HubALPN},
		},
		now:      time.Now,
		conns:    map[*hubConn]bool{},
		topics:   map[string]*hubTopic{},
		guests:   map[string]*guestTopic{},
		inflight: map[netip.Addr]int{},
		fails:    map[netip.Addr]*hubFail{},
		pending:  map[net.Conn]bool{},
	}, nil
}

// Serve takes connections on ln (a TCP listener, or SplitTCP's hub side)
// until ln fails or the hub closes; after Close it returns nil.
func (h *Hub) Serve(ln net.Listener) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	h.listeners = append(h.listeners, ln)
	h.mu.Unlock()
	for {
		raw, err := ln.Accept()
		if err != nil {
			h.mu.Lock()
			closed := h.closed
			h.mu.Unlock()
			if closed {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handle(raw)
		}()
	}
}

// Close stops every listener and connection and closes guest topics.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	lns := h.listeners
	for c := range h.pending {
		_ = c.Close()
	}
	conns := make([]*hubConn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	var legs []*hubLocalLeg
	for _, t := range h.topics {
		legs = append(legs, t.local...)
	}
	var bridges []Leg
	for topic, g := range h.guests {
		g.timer.Stop()
		if g.orphan != nil {
			g.orphan.Stop()
		}
		if g.bridge != nil {
			bridges = append(bridges, g.bridge)
		}
		delete(h.guests, topic)
	}
	h.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	for _, c := range conns {
		c.close()
	}
	for _, l := range legs {
		l.q.stop()
	}
	for _, b := range bridges {
		b.Close()
	}
	h.wg.Wait()
}

func remoteAddr(c net.Conn) netip.AddrPort {
	return addrPortOf(c.RemoteAddr())
}

// admit counts a handshake from ip (its limitKey), or refuses it
// (backoff, too many from there, too many in all).
func (h *Hub) admit(ip netip.Addr) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	if f := h.fails[ip]; f != nil && h.now().Before(f.until) {
		return false
	}
	if h.inflight[ip] >= h.lim.HandshakesPerIP || h.nInflight >= h.lim.Handshakes {
		return false
	}
	h.inflight[ip]++
	h.nInflight++
	return true
}

func (h *Hub) setPending(c net.Conn, on bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if on {
		if h.closed {
			return false
		}
		h.pending[c] = true
	} else {
		delete(h.pending, c)
	}
	return true
}

// handshakeDone ends a handshake admit counted. A failed one backs the IP
// off, unless it failed only for a reason an honest client hits (a guest
// whose topic isn't open yet).
func (h *Hub) handshakeDone(ip netip.Addr, res handshakeResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inflight[ip]--; h.inflight[ip] <= 0 {
		delete(h.inflight, ip)
	}
	h.nInflight--
	switch res {
	case handshakeOK:
		delete(h.fails, ip)
		return
	case handshakeNotOpen:
		return
	}
	if h.lim.FailBackoff < 0 {
		return
	}
	f := h.fails[ip]
	if f == nil {
		f = &hubFail{backoff: h.lim.FailBackoff}
		h.fails[ip] = f
	} else {
		f.backoff = min(f.backoff*2, 30*time.Second)
	}
	f.until = h.now().Add(f.backoff)
	if len(h.fails) > 4096 {
		for k, v := range h.fails {
			if h.now().After(v.until) {
				delete(h.fails, k)
			}
		}
	}
}

// handle runs one connection: TLS, hello, welcome, then frames. Anything
// wrong before the welcome closes it without a reply.
func (h *Hub) handle(raw net.Conn) {
	remote := remoteAddr(raw)
	ip := limitKey(remote.Addr())
	if !h.admit(ip) {
		_ = raw.Close()
		return
	}
	if !h.setPending(raw, true) {
		h.handshakeDone(ip, handshakeNotOpen)
		_ = raw.Close()
		return
	}
	c, res := h.handshake(raw, remote)
	h.setPending(raw, false)
	h.handshakeDone(ip, res)
	if res != handshakeOK {
		_ = raw.Close()
		return
	}
	h.serveConn(c)
}

type handshakeResult int

const (
	handshakeOK      handshakeResult = iota
	handshakeFailed                  // counts toward the IP's backoff
	handshakeNotOpen                 // a guest's topic isn't open, or the hub is full: no backoff
)

func (h *Hub) handshake(raw net.Conn, remote netip.AddrPort) (*hubConn, handshakeResult) {
	deadline := time.Now().Add(hubHelloTimeout)
	_ = raw.SetDeadline(deadline)
	tc := tls.Server(raw, h.tlsCfg)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, handshakeFailed
	}
	x, err := hubExporter(tc.ConnectionState())
	if err != nil {
		return nil, handshakeFailed
	}
	typ, body, err := readFrame(tc, 4<<10)
	if err != nil || typ != frameHello {
		return nil, handshakeFailed
	}
	var hello hubHello
	if parseJSON(body, &hello) != nil || hello.V != 1 {
		return nil, handshakeFailed
	}
	c := &hubConn{h: h, tc: tc, subs: map[string]bool{}, wants: map[string]bool{}, out: make(chan []byte, 256), done: make(chan struct{}),
		rate: newRate(h.lim.PubRate, h.lim.PubBurst)}
	if hello.Guest {
		c.peer = HubPeer{Guest: true, Remote: remote}
		c.guestTopic = hello.Topic
	} else {
		if !verifyHubSig(hubClientContext, x, hello.ID, hello.Pub, hello.Sig) {
			return nil, handshakeFailed
		}
		pub := ed25519.PublicKey(hello.Pub)
		person := ""
		if err := h.cfg.Authorize(hello.ID, pub); err != nil {
			if h.cfg.AuthorizeBoard == nil {
				h.cfg.Logf("hub: refused %s: %v", hello.ID, err)
				return nil, handshakeFailed
			}
			p, berr := h.cfg.AuthorizeBoard(hello.ID, pub)
			if berr != nil || p == "" {
				h.cfg.Logf("hub: refused %s: %v", hello.ID, cmpErr(berr, err))
				return nil, handshakeFailed
			}
			person = p
		}
		c.peer = HubPeer{ID: hello.ID, Pub: pub, Remote: remote, Person: person}
	}
	if res := h.register(c); res != handshakeOK {
		return nil, res
	}
	sig := h.cfg.Identity.Sign(hubSigPayload(hubServerContext, x, h.cfg.Self))
	w := hubWelcome{V: 1, ID: h.cfg.Self, Pub: h.cfg.Identity.Pub, Sig: sig}
	if err := writeFrame(tc, frameWelcome, marshal(w)); err != nil {
		h.unregister(c)
		return nil, handshakeFailed
	}
	_ = raw.SetDeadline(time.Time{})
	return c, handshakeOK
}

// register adds an authenticated connection, within the limits. A guest is
// admitted only while its topic is open.
func (h *Hub) register(c *hubConn) handshakeResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return handshakeNotOpen
	}
	members, guests, boards := 0, 0, 0
	for o := range h.conns {
		switch {
		case o.peer.Guest:
			guests++
		case o.peer.Person != "":
			boards++
		default:
			members++
		}
	}
	switch {
	case c.peer.Guest:
		if _, open := h.guests[c.guestTopic]; !open || guests >= h.lim.Guests {
			return handshakeNotOpen
		}
	case c.peer.Person != "":
		if boards >= h.lim.BoardPeers {
			return handshakeNotOpen
		}
	case members >= h.lim.Members:
		return handshakeNotOpen
	}
	h.conns[c] = true
	if !c.peer.Guest {
		// The owner is back: its guest topics stay open.
		for _, g := range h.guests {
			if g.owner == c.peer.ID && g.orphan != nil {
				g.orphan.Stop()
				g.orphan = nil
			}
		}
	}
	return handshakeOK
}

func (h *Hub) unregister(c *hubConn) {
	h.mu.Lock()
	if !h.conns[c] {
		h.mu.Unlock()
		return
	}
	delete(h.conns, c)
	for topic := range c.subs {
		h.unsubLocked(c, topic)
	}
	// A member's guest topics close hubGuestGrace after its last
	// connection drops, so a blip in its network doesn't end a pairing.
	if !c.peer.Guest && !h.memberConnectedLocked(c.peer.ID) {
		for topic, g := range h.guests {
			if g.owner == c.peer.ID && g.orphan == nil {
				g.orphan = time.AfterFunc(hubGuestGrace, func() { h.orphaned(topic, g) })
			}
		}
	}
	turnUsers := c.turnUsers
	h.mu.Unlock()
	if h.cfg.TURN != nil {
		for _, u := range turnUsers {
			h.cfg.TURN.revokeGuest(u)
		}
	}
}

func (h *Hub) memberConnectedLocked(id string) bool {
	for o := range h.conns {
		if !o.peer.Guest && o.peer.ID == id {
			return true
		}
	}
	return false
}

// orphaned closes a guest topic whose owner didn't come back in time.
func (h *Hub) orphaned(topic string, g *guestTopic) {
	h.mu.Lock()
	gone := h.guests[topic] == g && g.orphan != nil && !h.memberConnectedLocked(g.owner)
	h.mu.Unlock()
	if gone {
		h.CloseGuest(topic)
	}
}

func (h *Hub) unsubLocked(c *hubConn, topic string) {
	delete(c.subs, topic)
	if t := h.topics[topic]; t != nil {
		delete(t.remote, c)
		h.gcTopicLocked(topic)
	}
}

func (h *Hub) gcTopicLocked(topic string) {
	if t := h.topics[topic]; t != nil && len(t.remote) == 0 && len(t.local) == 0 {
		delete(h.topics, topic)
	}
}

// allowedLocked reports whether c may use topic.
func (h *Hub) allowedLocked(c *hubConn, topic string) bool {
	if c.peer.Person != "" {
		// A board peer: only what the app grants it, never a guest topic.
		if _, guest := h.guests[topic]; guest || h.cfg.AllowTopic == nil {
			return false
		}
		return h.cfg.AllowTopic(c.peer, topic)
	}
	if g, open := h.guests[topic]; open && h.now().Before(g.expires) {
		return !c.peer.Guest || topic == c.guestTopic
	}
	if c.peer.Guest {
		return false
	}
	if h.cfg.AllowTopic != nil {
		return h.cfg.AllowTopic(c.peer, topic)
	}
	t := h.topics[topic]
	return t != nil && len(t.local) > 0
}

// route hands one payload to every subscriber of topic but the sender, and
// to the LAN bridge if the topic is an open guest topic and the payload
// didn't come from there.
func (h *Hub) route(topic string, payload []byte, fromConn *hubConn, fromLocal *hubLocalLeg, fromBridge bool) {
	h.mu.Lock()
	t := h.topics[topic]
	var remote []*hubConn
	var local []*hubLocalLeg
	if t != nil {
		for c := range t.remote {
			if c != fromConn {
				remote = append(remote, c)
			}
		}
		for _, l := range t.local {
			if l != fromLocal {
				local = append(local, l)
			}
		}
	}
	var bridge Leg
	if g := h.guests[topic]; g != nil && !fromBridge {
		bridge = g.bridge
	}
	h.mu.Unlock()
	if len(remote) > 0 {
		body, err := topicBody(topic, payload)
		if err != nil {
			return
		}
		frame := frameBytes(frameMsg, body)
		for _, c := range remote {
			c.send(frame)
		}
	}
	for _, l := range local {
		l.q.push(payload)
	}
	if bridge != nil {
		_ = bridge.Publish("", payload)
	}
}

// OpenGuest opens a guest topic for the server's own pairing window: guests
// naming it in their hello are admitted until ttl (at most MaxGuestTTL) or
// CloseGuest.
func (h *Hub) OpenGuest(topic string, ttl time.Duration) error {
	return h.openGuest(topic, ttl, "", false)
}

// OpenInvite opens an invite guest topic for the server's own invite
// window (a shared board's invite): as OpenGuest, for at most MaxInviteTTL.
func (h *Hub) OpenInvite(topic string, ttl time.Duration) error {
	return h.openGuest(topic, ttl, "", true)
}

func (h *Hub) openGuest(topic string, ttl time.Duration, owner string, invite bool) error {
	if topic == "" || len(topic) > 255 {
		return errors.New("room: bad guest topic")
	}
	max := MaxGuestTTL
	if invite {
		max = MaxInviteTTL
	}
	if ttl <= 0 || ttl > max {
		ttl = max
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return ErrClosed
	}
	if g := h.guests[topic]; g != nil {
		if g.owner != owner || g.invite != invite {
			h.mu.Unlock()
			return errors.New("room: guest topic held by another member")
		}
		g.expires = h.now().Add(ttl)
		g.timer.Reset(ttl)
		h.mu.Unlock()
		return nil
	}
	if owner != "" {
		n, limit := 0, h.lim.GuestsPerMember
		if invite {
			limit = h.lim.InvitesPerMember
		}
		for _, g := range h.guests {
			if g.owner == owner && g.invite == invite {
				n++
			}
		}
		if n >= limit {
			h.mu.Unlock()
			return errors.New("room: too many guest topics open")
		}
	}
	g := &guestTopic{owner: owner, invite: invite, expires: h.now().Add(ttl)}
	g.timer = time.AfterFunc(ttl, func() { h.expireGuest(topic, g) })
	h.guests[topic] = g
	h.regrantLocked(topic)
	h.mu.Unlock()
	if h.cfg.Bridge != nil {
		leg, err := h.cfg.Bridge.Carrier().Join(topic, func(p []byte, _ netip.AddrPort) { h.route(topic, p, nil, nil, true) }, nil)
		if err == nil {
			h.mu.Lock()
			if h.guests[topic] == g {
				g.bridge = leg
				leg = nil
			}
			h.mu.Unlock()
			if leg != nil {
				leg.Close()
			}
		}
	}
	return nil
}

func (h *Hub) expireGuest(topic string, g *guestTopic) {
	h.mu.Lock()
	// A renewal may have reset the timer after this fire was queued.
	stale := h.guests[topic] == g && !h.now().Before(g.expires)
	h.mu.Unlock()
	if stale {
		h.CloseGuest(topic)
	}
}

// CloseGuest closes a guest topic and drops its guests; members still
// subscribed keep it only if AllowTopic allows it on its own.
func (h *Hub) CloseGuest(topic string) {
	h.mu.Lock()
	g := h.guests[topic]
	if g == nil {
		h.mu.Unlock()
		return
	}
	g.timer.Stop()
	if g.orphan != nil {
		g.orphan.Stop()
	}
	delete(h.guests, topic)
	var drop []*hubConn
	for c := range h.conns {
		if c.peer.Guest && c.guestTopic == topic {
			drop = append(drop, c)
		} else if c.subs[topic] && !h.allowedLocked(c, topic) {
			h.unsubLocked(c, topic)
		}
	}
	h.mu.Unlock()
	if g.bridge != nil {
		g.bridge.Close()
	}
	for _, c := range drop {
		c.close()
	}
}

// Drop closes every connection of member id and its guest topics (a
// revoke). Authorize must refuse id from now on, or it reconnects.
func (h *Hub) Drop(id string) {
	h.mu.Lock()
	var drop []*hubConn
	for c := range h.conns {
		if !c.peer.Guest && c.peer.ID == id {
			drop = append(drop, c)
		}
	}
	var topics []string
	for topic, g := range h.guests {
		if g.owner == id {
			topics = append(topics, topic)
		}
	}
	h.mu.Unlock()
	for _, t := range topics {
		h.CloseGuest(t)
	}
	for _, c := range drop {
		c.sendNow(frameErr, marshal(hubErrBody{Reason: "revoked"}))
		c.close()
	}
}

// Recheck applies AllowTopic again to every connection: a subscription it
// no longer allows ends, and one asked for that it now allows starts. Call
// it after the state AllowTopic reads changes (a board's members or epoch).
// To drop another person's devices entirely, Drop each of them (Peers lists
// them with their Person).
func (h *Hub) Recheck() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.conns {
		for topic := range c.subs {
			if !h.allowedLocked(c, topic) {
				h.unsubLocked(c, topic)
			}
		}
		for topic := range c.wants {
			h.grantLocked(c, topic)
		}
	}
}

// Peers lists the connected clients.
func (h *Hub) Peers() []HubPeer {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HubPeer, 0, len(h.conns))
	for c := range h.conns {
		out = append(out, c.peer)
	}
	return out
}

// --- one connection ------------------------------------------------------

type hubConn struct {
	h          *Hub
	tc         *tls.Conn
	peer       HubPeer
	guestTopic string
	subs       map[string]bool // granted subscriptions, under h.mu
	wants      map[string]bool // every topic asked for (subs among them), under h.mu
	turnUsers  []string        // guest TURN users issued here, under h.mu
	rate       *rate

	out  chan []byte
	done chan struct{}
	once sync.Once
	wmu  sync.Mutex
}

// send queues a frame; a connection that can't keep up loses frames, as a
// congested broker would.
func (c *hubConn) send(frame []byte) {
	select {
	case c.out <- frame:
	case <-c.done:
	default:
	}
}

// sendNow writes a frame directly (before a close).
func (c *hubConn) sendNow(typ byte, body []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.tc.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeFrame(c.tc, typ, body)
}

func (c *hubConn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.tc.Close()
	})
}

func (c *hubConn) writer() {
	for {
		select {
		case <-c.done:
			return
		case f := <-c.out:
			c.wmu.Lock()
			_ = c.tc.SetWriteDeadline(time.Now().Add(hubWriteTimeout))
			_, err := c.tc.Write(f)
			c.wmu.Unlock()
			if err != nil {
				c.close()
				return
			}
		}
	}
}

func (h *Hub) serveConn(c *hubConn) {
	defer h.unregister(c)
	defer c.close()
	go c.writer()
	for {
		_ = c.tc.SetReadDeadline(time.Now().Add(hubIdleTimeout))
		typ, body, err := readFrame(c.tc, MaxHubFrame)
		if err != nil {
			return
		}
		switch typ {
		case framePing:
			c.send(frameBytes(framePong, nil))
		case framePong:
		case frameSub:
			h.sub(c, string(body))
		case frameUnsub:
			h.mu.Lock()
			delete(c.wants, string(body))
			h.unsubLocked(c, string(body))
			h.mu.Unlock()
		case framePub:
			topic, payload, ok := splitTopicBody(body)
			if !ok || !c.rate.take() {
				continue
			}
			h.mu.Lock()
			subbed := c.subs[topic] && h.allowedLocked(c, topic)
			h.mu.Unlock()
			if subbed {
				h.route(topic, payload, c, nil, false)
			}
		case frameGuestOpen, frameGuestClose:
			if c.peer.Guest {
				return
			}
			if c.peer.Person != "" {
				h.cfg.Logf("hub: board peer %s may not open guest topics", c.peer.ID)
				continue
			}
			var g hubGuestBody
			if parseJSON(body, &g) != nil {
				continue
			}
			if typ == frameGuestOpen {
				if err := h.openGuest(g.Topic, time.Duration(g.TTLMs)*time.Millisecond, c.peer.ID, g.Kind == GuestInvite); err != nil {
					h.cfg.Logf("hub: guest.open from %s: %v", c.peer.ID, err)
				}
			} else {
				h.mu.Lock()
				gt := h.guests[g.Topic]
				mine := gt != nil && gt.owner == c.peer.ID
				h.mu.Unlock()
				if mine {
					h.CloseGuest(g.Topic)
				}
			}
		case frameTURNGet:
			var req hubTURNBody
			_ = parseJSON(body, &req)
			reply := h.turnFor(c)
			reply.ID = req.ID
			c.send(frameBytes(frameTURNCreds, marshal(reply)))
		}
	}
}

// sub records that c wants topic and grants it if allowed now. A topic
// that isn't allowed yet (the server's own room hasn't opened it, or a
// guest window isn't open) is granted later, when it becomes allowed, with
// no new sub frame: see regrantLocked.
func (h *Hub) sub(c *hubConn, topic string) {
	if topic == "" || len(topic) > 255 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !c.wants[topic] {
		if len(c.wants) >= h.lim.TopicsPerConn {
			return
		}
		c.wants[topic] = true
	}
	h.grantLocked(c, topic)
}

func (h *Hub) grantLocked(c *hubConn, topic string) {
	if c.subs[topic] || !h.allowedLocked(c, topic) {
		return
	}
	c.subs[topic] = true
	t := h.topics[topic]
	if t == nil {
		t = &hubTopic{remote: map[*hubConn]bool{}}
		h.topics[topic] = t
	}
	t.remote[c] = true
}

// regrantLocked grants topic to every connection that asked for it and
// may have it now.
func (h *Hub) regrantLocked(topic string) {
	for c := range h.conns {
		if c.wants[topic] {
			h.grantLocked(c, topic)
		}
	}
}

// turnFor is the turn.creds answer: a member's own, or a guest's narrower
// ones until its topic closes. Empty when there is no TURN server.
func (h *Hub) turnFor(c *hubConn) hubTURNBody {
	if h.cfg.TURN == nil {
		return hubTURNBody{}
	}
	var tc TURNCreds
	if c.peer.Guest {
		h.mu.Lock()
		g := h.guests[c.guestTopic]
		if g == nil || len(c.turnUsers) >= 4 {
			h.mu.Unlock()
			return hubTURNBody{}
		}
		until := g.expires
		h.mu.Unlock()
		tc = h.cfg.TURN.IssueGuest(until)
		if _, user, ok := strings.Cut(tc.Username, ":"); ok {
			h.mu.Lock()
			c.turnUsers = append(c.turnUsers, user)
			h.mu.Unlock()
		}
	} else if c.peer.Person != "" {
		tc = h.cfg.TURN.IssueBoard(c.peer.Person)
	} else {
		tc = h.cfg.TURN.Issue(c.peer.ID)
	}
	b := hubTURNBody{Username: tc.Username, Credential: tc.Credential, TTLS: int64(tc.TTL / time.Second)}
	if h.cfg.PublicUDP != nil {
		if ap := h.cfg.PublicUDP(); ap.IsValid() {
			b.UDP = ap.String()
		}
	}
	return b
}

// --- the server's own rooms ----------------------------------------------

// Local is the hub as a Carrier for the server's own rooms, in process:
// they are subscribers like any connection, without TLS. By default the
// topics they join are the ones members may subscribe to.
func (h *Hub) Local() Carrier { return hubLocalCarrier{h} }

type hubLocalCarrier struct{ h *Hub }

func (c hubLocalCarrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (Leg, error) {
	h := c.h
	if topic == "" || len(topic) > 255 {
		return nil, errors.New("room: hub topic must be 1-255 bytes")
	}
	l := &hubLocalLeg{h: h, topic: topic, q: newQueue(func(p []byte) { deliver(p, netip.AddrPort{}) })}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	t := h.topics[topic]
	if t == nil {
		t = &hubTopic{remote: map[*hubConn]bool{}}
		h.topics[topic] = t
	}
	t.local = append(t.local, l)
	h.regrantLocked(topic)
	h.mu.Unlock()
	if up != nil {
		go up()
	}
	return l, nil
}

type hubLocalLeg struct {
	h      *Hub
	topic  string
	q      *queue
	mu     sync.Mutex
	closed bool
}

func (l *hubLocalLeg) Publish(_ string, payload []byte) error {
	if !l.Up() {
		return ErrClosed
	}
	l.h.route(l.topic, payload, nil, l, false)
	return nil
}

func (l *hubLocalLeg) Seen(string, netip.AddrPort) {}

func (l *hubLocalLeg) Up() bool {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return false
	}
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	return !l.h.closed
}

func (l *hubLocalLeg) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	h := l.h
	h.mu.Lock()
	if t := h.topics[l.topic]; t != nil {
		for i, x := range t.local {
			if x == l {
				t.local = append(t.local[:i:i], t.local[i+1:]...)
				break
			}
		}
		h.gcTopicLocked(l.topic)
	}
	// Members subscribed only because this room was open lose the topic.
	for c := range h.conns {
		if c.subs[l.topic] && !h.allowedLocked(c, l.topic) {
			h.unsubLocked(c, l.topic)
		}
	}
	h.mu.Unlock()
	l.q.stop()
}

// --- helpers -------------------------------------------------------------

// queue delivers payloads in order on its own goroutine, outside every
// lock, so a receiver may publish from its callback.
type queue struct {
	fn   func([]byte)
	mu   sync.Mutex
	q    [][]byte
	wake chan struct{}
	done chan struct{}
	once sync.Once
}

func newQueue(fn func([]byte)) *queue {
	q := &queue{fn: fn, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go q.loop()
	return q
}

func (q *queue) push(p []byte) {
	q.mu.Lock()
	if len(q.q) < 1024 {
		q.q = append(q.q, append([]byte(nil), p...))
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue) stop() { q.once.Do(func() { close(q.done) }) }

func (q *queue) loop() {
	for {
		select {
		case <-q.done:
			return
		case <-q.wake:
		}
		for {
			select {
			case <-q.done:
				return
			default:
			}
			q.mu.Lock()
			if len(q.q) == 0 {
				q.mu.Unlock()
				break
			}
			p := q.q[0]
			q.q = q.q[1:]
			q.mu.Unlock()
			q.fn(p)
		}
	}
}

// rate is a token bucket of frames.
type rate struct {
	mu     sync.Mutex
	per    float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRate(per, burst float64) *rate {
	return &rate{per: per, burst: burst, tokens: burst, last: time.Now()}
}

func (r *rate) take() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens = min(r.burst, r.tokens+now.Sub(r.last).Seconds()*r.per)
	r.last = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// cmpErr is a when it's set, else b.
func cmpErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
