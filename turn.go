package room

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TURN REST credentials are HMAC-SHA1 by definition
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// The TURN server a home server runs (pion/turn), so devices on networks
// that block direct paths still connect, and STUN for devices away from
// home. Credentials are the TURN REST scheme, minted by the app (over its
// hub) and never fetched over HTTP:
//
//	username   = "<expiry unix seconds>:<handle>"
//	credential = base64(HMAC-SHA1(key, username))
//
// A member's handle is "~" and its user (a device id) masked with a
// keystream from the key and the expiry, so the USERNAME that crosses every
// network a device roams in names no stable id; a guest's is its random
// "guest-" user. The key never leaves the server. Every authenticated
// request, allocation refreshes included, asks the app's Authorize again, so
// a revoked device loses its relay at its next refresh rather than at
// expiry.

// TURN defaults.
const (
	DefaultTURNTTL      = 12 * time.Hour
	DefaultTURNRealm    = "relay"
	DefaultMaxPerUser   = 8
	DefaultMaxTotal     = 32
	DefaultMaxGuests    = 4  // allocations across every guest
	DefaultMaxBoardUser = 4  // allocations per other person (a board user)
	DefaultMaxTCP       = 64 // TURN-over-TCP connections
	DefaultMaxTCPPerIP  = 8
	turnAllocLifetime   = 10 * time.Minute
	guestUserPrefix     = "guest-"
	boardUserPrefix     = "board-"
	memberHandlePrefix  = "~"
	turnSrcCap          = 4096 // remembered client addresses (for the peer filter)
	turnSrcForgetAfter  = time.Hour
	turnRefusedLogEvery = 10 * time.Second
)

// turnTCPIdle closes a TURN-over-TCP connection that sends nothing for this
// long. Clients refresh permissions every few minutes and ChannelData flows
// while a path is in use, so only a silent connection hits it. A variable
// so tests can run fast.
var turnTCPIdle = 5 * time.Minute

var (
	errTURNTCPRelay    = errors.New("room: tcp relay allocations are not supported")
	errTURNUserQuota   = errors.New("room: too many allocations for this user")
	errTURNServerQuota = errors.New("room: relay is full")
	errTURNNotIPv4     = errors.New("room: only IPv4 relay allocations are supported")
)

// TURNConfig sets up a TURN server on sockets the app opened.
type TURNConfig struct {
	// UDP is the UDP socket (port N); STUN Binding is answered there too.
	UDP net.PacketConn
	// TCP, when set, takes TURN over TCP (SplitTCP's TURN side).
	TCP net.Listener
	// RelayIP is where relayed sockets bind: the server's LAN address
	// (tests: 127.0.0.1). It must be IPv4.
	RelayIP netip.Addr
	// Key is the HMAC key credentials are made with; the app keeps it.
	Key [32]byte
	// Realm defaults to DefaultTURNRealm.
	Realm string
	// TTL is how long issued credentials last (default 12 h). A relayed
	// connection lasts only as long as the credentials it was made with.
	TTL time.Duration
	// Authorize is asked on every authenticated request with the user from
	// the username (a device id, or "board-<person>" for another person's
	// devices, IssueBoard); non-nil refuses. Guest users are checked by the
	// server itself. nil admits every user with valid credentials.
	Authorize func(user string) error
	// AllowPeer decides which peer addresses a user may relay to, on every
	// permission and every packet out. nil: members to this host's private
	// subnets and to relayed addresses on this server; guests only to
	// relayed addresses. Loopback, link-local, multicast and public
	// addresses are never in the default. Board users (IssueBoard) relay
	// only to this server's relayed addresses whatever AllowPeer says.
	AllowPeer func(user string, ip netip.Addr) bool
	// MaxPerUser and MaxTotal cap allocations (defaults 8 and 32);
	// MaxGuests caps the allocations of every guest together (default 4),
	// so pairing guests never take the relay from members.
	MaxPerUser, MaxTotal, MaxGuests int
	// MaxBoardPerUser caps one other person's allocations, across all of
	// their devices (default 4), inside MaxTotal.
	MaxBoardPerUser int
	// MaxTCP and MaxTCPPerIP cap TURN-over-TCP connections (defaults 64
	// and 8; an IPv6 /64 counts as one IP).
	MaxTCP, MaxTCPPerIP int
	// Logf, when set, gets diagnostics (never credentials).
	Logf func(format string, args ...any)
}

// TURNServer is a running TURN server.
type TURNServer struct {
	cfg     TURNConfig
	srv     *turn.Server
	subnets []netip.Prefix
	udpPort uint16
	now     func() time.Time

	mu         sync.Mutex
	guests     map[string]time.Time // guest user -> credentials valid until
	srcs       map[string]srcUser   // client transport address -> user, after a verified request
	users      map[string]int       // allocations per user
	total      int
	guestTotal int
	relays     map[uint16]bool                        // relayed ports in use
	conns      map[string]map[*turnRelayConn]struct{} // allocations per guest user
	refusedAt  time.Time                              // last "refused" log line
	refusedN   int                                    // refusals not logged since
}

type srcUser struct {
	user string
	at   time.Time
}

// NewTURN starts the TURN server.
func NewTURN(cfg TURNConfig) (*TURNServer, error) {
	if cfg.UDP == nil && cfg.TCP == nil {
		return nil, errors.New("room: TURN needs a UDP socket or a TCP listener")
	}
	if !cfg.RelayIP.Is4() {
		return nil, errors.New("room: TURN relay address must be IPv4")
	}
	if cfg.Key == ([32]byte{}) {
		return nil, errors.New("room: TURN key is empty")
	}
	if cfg.Realm == "" {
		cfg.Realm = DefaultTURNRealm
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTURNTTL
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = DefaultMaxPerUser
	}
	if cfg.MaxTotal <= 0 {
		cfg.MaxTotal = DefaultMaxTotal
	}
	if cfg.MaxGuests <= 0 {
		cfg.MaxGuests = DefaultMaxGuests
	}
	if cfg.MaxBoardPerUser <= 0 {
		cfg.MaxBoardPerUser = DefaultMaxBoardUser
	}
	if cfg.MaxTCP <= 0 {
		cfg.MaxTCP = DefaultMaxTCP
	}
	if cfg.MaxTCPPerIP <= 0 {
		cfg.MaxTCPPerIP = DefaultMaxTCPPerIP
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	t := &TURNServer{
		cfg:    cfg,
		now:    time.Now,
		guests: map[string]time.Time{},
		srcs:   map[string]srcUser{},
		users:  map[string]int{},
		relays: map[uint16]bool{},
		conns:  map[string]map[*turnRelayConn]struct{}{},
	}
	for _, s := range LocalSubnets() {
		t.subnets = append(t.subnets, s.Prefix.Masked())
	}
	if cfg.UDP != nil {
		t.udpPort = addrPortOf(cfg.UDP.LocalAddr()).Port()
	}
	gen := &turnRelayGen{t: t, inner: &turn.RelayAddressGeneratorStatic{
		RelayAddress: net.IP(cfg.RelayIP.AsSlice()),
		Address:      cfg.RelayIP.String(),
	}}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	sc := turn.ServerConfig{
		Realm:              cfg.Realm,
		AuthHandler:        t.auth,
		LoggerFactory:      lf,
		AllocationLifetime: turnAllocLifetime,
		// pion asks AuthHandler before it checks MESSAGE-INTEGRITY, so a
		// client's address is learned only here, once the check passed.
		EventHandler: turn.EventHandler{OnAuth: t.onAuth, OnAllocationDeleted: t.onAllocDeleted},
	}
	if cfg.UDP != nil {
		sc.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: cfg.UDP, RelayAddressGenerator: gen, PermissionHandler: t.permit}}
	}
	if cfg.TCP != nil {
		ln := &turnTCPListener{Listener: cfg.TCP, max: cfg.MaxTCP, perIP: cfg.MaxTCPPerIP, byIP: map[netip.Addr]int{}}
		sc.ListenerConfigs = []turn.ListenerConfig{{Listener: ln, RelayAddressGenerator: gen, PermissionHandler: t.permit}}
	}
	srv, err := turn.NewServer(sc)
	if err != nil {
		return nil, err
	}
	t.srv = srv
	return t, nil
}

// Close stops the server and closes its sockets.
func (t *TURNServer) Close() {
	if t.srv != nil {
		_ = t.srv.Close()
	}
}

// Issue mints credentials for user (a device id; no ':').
func (t *TURNServer) Issue(user string) TURNCreds {
	return t.mint(user, t.now().Add(t.cfg.TTL))
}

// IssueBoard mints credentials for another person's devices on a shared
// board: one user per person ("board-" + person, no ':'), so they share
// MaxBoardPerUser allocations. Their allocations relay only to this
// server's relayed addresses, never to the LAN.
func (t *TURNServer) IssueBoard(person string) TURNCreds {
	return t.Issue(boardUserPrefix + person)
}

// IssueGuest mints credentials for a pairing guest, valid until until (at
// most the TTL). A guest's allocation may send only to relayed addresses on
// this server, unless AllowPeer says otherwise.
func (t *TURNServer) IssueGuest(until time.Time) TURNCreds {
	if limit := t.now().Add(t.cfg.TTL); until.After(limit) {
		until = limit
	}
	user := guestUserPrefix + randHex(8)
	t.mu.Lock()
	for g, u := range t.guests {
		if !t.now().Before(u) {
			delete(t.guests, g)
		}
	}
	t.guests[user] = until
	t.mu.Unlock()
	return t.mint(user, until)
}

// revokeGuest ends a guest's credentials early (its pairing window closed)
// and closes the allocations it made, so they don't hold the guest pool
// until their next refresh.
func (t *TURNServer) revokeGuest(user string) {
	t.mu.Lock()
	delete(t.guests, user)
	var conns []*turnRelayConn
	for c := range t.conns[user] {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (t *TURNServer) mint(user string, until time.Time) TURNCreds {
	exp := strconv.FormatInt(until.Unix(), 10)
	name := exp + ":" + t.handle(user, exp)
	return TURNCreds{Username: name, Credential: t.credential(name), TTL: until.Sub(t.now()).Truncate(time.Second)}
}

// handle is the username's part after the expiry: a guest's random user as
// it is, a member's masked (see the top of this file).
func (t *TURNServer) handle(user, exp string) string {
	if strings.HasPrefix(user, guestUserPrefix) {
		return user
	}
	b := []byte(user)
	for i, m := range t.mask(exp, len(b)) {
		b[i] ^= m
	}
	return memberHandlePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// mask is n bytes of HMAC-SHA256(key, label || exp || counter) keystream.
func (t *TURNServer) mask(exp string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		mac := hmac.New(sha256.New, t.cfg.Key[:])
		mac.Write([]byte("go-room/turn/user/1\x00"))
		mac.Write([]byte(exp))
		mac.Write([]byte{0, byte(i)})
		out = mac.Sum(out)
	}
	return out[:n]
}

// parseUsername reads "<expiry>:<handle>" back into the expiry and user.
// It checks nothing but the shape: the credential check comes after.
func (t *TURNServer) parseUsername(username string) (int64, string, bool) {
	exp, h, ok := strings.Cut(username, ":")
	if !ok || h == "" {
		return 0, "", false
	}
	e, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return 0, "", false
	}
	if strings.HasPrefix(h, guestUserPrefix) {
		return e, h, true
	}
	masked, ok := strings.CutPrefix(h, memberHandlePrefix)
	if !ok {
		return 0, "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(masked)
	if err != nil || len(b) == 0 || len(b) > 255 {
		return 0, "", false
	}
	for i, m := range t.mask(exp, len(b)) {
		b[i] ^= m
	}
	return e, string(b), true
}

func (t *TURNServer) credential(username string) string {
	mac := hmac.New(sha1.New, t.cfg.Key[:])
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// auth is pion's AuthHandler: the REST credential check, then the app's
// Authorize (or the guest list), on every authenticated request. pion
// checks MESSAGE-INTEGRITY only after this returns, so nothing here may
// record anything about the client: onAuth does, once the check passed.
func (t *TURNServer) auth(ra *turn.RequestAttributes) (string, []byte, bool) {
	e, user, ok := t.parseUsername(ra.Username)
	if !ok || e < t.now().Unix() {
		return "", nil, false
	}
	if strings.HasPrefix(user, guestUserPrefix) {
		t.mu.Lock()
		until, ok := t.guests[user]
		t.mu.Unlock()
		if !ok || !t.now().Before(until) {
			return "", nil, false
		}
	} else if t.cfg.Authorize != nil {
		if err := t.cfg.Authorize(user); err != nil {
			t.logRefused(user, err)
			return "", nil, false
		}
	}
	return user, turn.GenerateAuthKey(ra.Username, ra.Realm, t.credential(ra.Username)), true
}

// logRefused logs a refused user at most once per turnRefusedLogEvery, so
// a flood of requests can't fill the log.
func (t *TURNServer) logRefused(user string, err error) {
	t.mu.Lock()
	now := t.now()
	if now.Sub(t.refusedAt) < turnRefusedLogEvery {
		t.refusedN++
		t.mu.Unlock()
		return
	}
	n := t.refusedN
	t.refusedAt, t.refusedN = now, 0
	t.mu.Unlock()
	if n > 0 {
		t.cfg.Logf("turn: refused %q: %v (and %d more refusals)", user, err, n)
		return
	}
	t.cfg.Logf("turn: refused %q: %v", user, err)
}

// onAuth is pion's OnAuth event, after MESSAGE-INTEGRITY: a verified
// request is what teaches permit which user an address belongs to.
func (t *TURNServer) onAuth(src, _ net.Addr, _, username, _, _ string, verdict bool) {
	if !verdict || src == nil {
		return
	}
	if _, user, ok := t.parseUsername(username); ok {
		t.rememberSrc(src.String(), user)
	}
}

func (t *TURNServer) onAllocDeleted(src, _ net.Addr, _, _, _ string) {
	if src == nil {
		return
	}
	t.mu.Lock()
	delete(t.srcs, src.String())
	t.mu.Unlock()
}

func (t *TURNServer) rememberSrc(src, user string) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.srcs[src]; !ok && len(t.srcs) >= turnSrcCap {
		for k, v := range t.srcs {
			if now.Sub(v.at) > turnSrcForgetAfter {
				delete(t.srcs, k)
			}
		}
		if len(t.srcs) >= turnSrcCap {
			return
		}
	}
	t.srcs[src] = srcUser{user: user, at: now}
}

// permit is pion's PermissionHandler. It gets the client's address, not the
// user, so the user is looked up from the last authenticated request from
// that address.
func (t *TURNServer) permit(client net.Addr, peer net.IP) bool {
	ip, ok := netip.AddrFromSlice(peer)
	if !ok || client == nil {
		return false
	}
	t.mu.Lock()
	su, known := t.srcs[client.String()]
	t.mu.Unlock()
	return known && t.allowPeer(su.user, ip.Unmap(), 0)
}

// allowPeer applies AllowPeer or the default. port is the destination port
// when a packet is being sent (0 for a permission).
func (t *TURNServer) allowPeer(user string, ip netip.Addr, port uint16) bool {
	relayed := func() bool {
		r := ip == t.cfg.RelayIP
		if r && port != 0 {
			t.mu.Lock()
			r = t.relays[port]
			t.mu.Unlock()
		}
		return r
	}
	if strings.HasPrefix(user, boardUserPrefix) {
		return relayed() // other people never reach the LAN, whatever AllowPeer says
	}
	if t.cfg.AllowPeer != nil {
		return t.cfg.AllowPeer(user, ip)
	}
	if r := relayed(); r || strings.HasPrefix(user, guestUserPrefix) {
		return r
	}
	if !ip.Is4() || !ip.IsPrivate() {
		return false // loopback, link-local, multicast, unspecified and public all fail here
	}
	for _, p := range t.subnets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// turnRelayGen allocates relayed sockets on RelayIP, counts them, and wraps
// each so every packet out passes the peer filter.
type turnRelayGen struct {
	t     *TURNServer
	inner *turn.RelayAddressGeneratorStatic
}

func (g *turnRelayGen) Validate() error { return g.inner.Validate() }

func (g *turnRelayGen) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	if conf.Network != "udp4" {
		return nil, nil, errTURNNotIPv4
	}
	t := g.t
	guest := strings.HasPrefix(conf.UserID, guestUserPrefix)
	t.mu.Lock()
	switch {
	case t.total >= t.cfg.MaxTotal:
		t.mu.Unlock()
		return nil, nil, errTURNServerQuota
	case guest && t.guestTotal >= t.cfg.MaxGuests:
		t.mu.Unlock()
		return nil, nil, errTURNServerQuota
	case strings.HasPrefix(conf.UserID, boardUserPrefix) && t.users[conf.UserID] >= t.cfg.MaxBoardPerUser:
		t.mu.Unlock()
		return nil, nil, errTURNUserQuota
	case t.users[conf.UserID] >= t.cfg.MaxPerUser:
		t.mu.Unlock()
		return nil, nil, errTURNUserQuota
	}
	t.users[conf.UserID]++
	t.total++
	if guest {
		t.guestTotal++
	}
	t.mu.Unlock()
	conn, addr, err := g.inner.AllocatePacketConn(conf)
	if err != nil {
		t.release(conf.UserID, 0, nil)
		return nil, nil, err
	}
	port := addrPortOf(conn.LocalAddr()).Port()
	rc := &turnRelayConn{PacketConn: conn, t: t, user: conf.UserID, port: port}
	t.mu.Lock()
	t.relays[port] = true
	_, live := t.guests[conf.UserID]
	if guest && live {
		if t.conns[conf.UserID] == nil {
			t.conns[conf.UserID] = map[*turnRelayConn]struct{}{}
		}
		t.conns[conf.UserID][rc] = struct{}{}
	}
	t.mu.Unlock()
	if guest && !live {
		// Revoked while this allocation was being made.
		_ = rc.Close()
		return nil, nil, errTURNServerQuota
	}
	return rc, addr, nil
}

func (g *turnRelayGen) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errTURNTCPRelay
}

func (g *turnRelayGen) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, errTURNTCPRelay
}

func (t *TURNServer) release(user string, port uint16, c *turnRelayConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.users[user]--; t.users[user] <= 0 {
		delete(t.users, user)
	}
	t.total--
	if strings.HasPrefix(user, guestUserPrefix) {
		t.guestTotal--
	}
	if port != 0 {
		delete(t.relays, port)
	}
	if set := t.conns[user]; set != nil && c != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(t.conns, user)
		}
	}
}

// turnRelayConn is one allocation's relayed socket. A packet the filter
// refuses is dropped silently, like a lossy link.
type turnRelayConn struct {
	net.PacketConn
	t    *TURNServer
	user string
	port uint16
	once sync.Once
}

func (c *turnRelayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst := addrPortOf(addr)
	if !dst.IsValid() || !c.t.allowPeer(c.user, dst.Addr(), dst.Port()) {
		return len(p), nil
	}
	// Never into the server's own TURN port from a relayed socket.
	if dst.Addr() == c.t.cfg.RelayIP && dst.Port() == c.t.udpPort {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *turnRelayConn) Close() error {
	err := net.ErrClosed
	c.once.Do(func() {
		c.t.release(c.user, c.port, c)
		err = c.PacketConn.Close()
	})
	return err
}

// turnTCPListener is the TURN side of port N as pion sees it: it caps the
// connections open (in total and per IP), and each connection closes after
// turnTCPIdle with nothing read, so one host can't hold sockets, goroutines
// and buffers on the server by sending a STUN-looking byte and going quiet.
type turnTCPListener struct {
	net.Listener
	max, perIP int

	mu   sync.Mutex
	n    int
	byIP map[netip.Addr]int
}

func (l *turnTCPListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := limitKey(remoteAddr(c).Addr())
		l.mu.Lock()
		ok := l.n < l.max && l.byIP[ip] < l.perIP
		if ok {
			l.n++
			l.byIP[ip]++
		}
		l.mu.Unlock()
		if !ok {
			_ = c.Close()
			continue
		}
		return &idleConn{Conn: c, done: func() { l.done(ip) }}, nil
	}
}

func (l *turnTCPListener) done(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n--
	if l.byIP[ip]--; l.byIP[ip] <= 0 {
		delete(l.byIP, ip)
	}
}

// idleConn pushes its read deadline turnTCPIdle ahead before every read.
type idleConn struct {
	net.Conn
	done func()
	once sync.Once
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(turnTCPIdle))
	return c.Conn.Read(p)
}

func (c *idleConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}
