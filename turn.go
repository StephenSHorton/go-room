package room

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TURN REST credentials are HMAC-SHA1 by definition
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
//	username   = "<expiry unix seconds>:<user>"
//	credential = base64(HMAC-SHA1(key, username))
//
// The key never leaves the server. Every authenticated request, allocation
// refreshes included, asks the app's Authorize again, so a revoked device
// loses its relay at its next refresh rather than at expiry.

// TURN defaults.
const (
	DefaultTURNTTL     = 12 * time.Hour
	DefaultTURNRealm   = "relay"
	DefaultMaxPerUser  = 8
	DefaultMaxTotal    = 32
	turnAllocLifetime  = 10 * time.Minute
	guestUserPrefix    = "guest-"
	turnSrcCap         = 4096 // remembered client addresses (for the peer filter)
	turnSrcForgetAfter = time.Hour
)

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
	// the username (a device id); non-nil refuses. Guest users are checked
	// by the server itself. nil admits every user with valid credentials.
	Authorize func(user string) error
	// AllowPeer decides which peer addresses a user may relay to, on every
	// permission and every packet out. nil: members to this host's private
	// subnets and to relayed addresses on this server; guests only to
	// relayed addresses. Loopback, link-local, multicast and public
	// addresses are never in the default.
	AllowPeer func(user string, ip netip.Addr) bool
	// MaxPerUser and MaxTotal cap allocations (defaults 8 and 32).
	MaxPerUser, MaxTotal int
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

	mu     sync.Mutex
	guests map[string]time.Time // guest user -> credentials valid until
	srcs   map[string]srcUser   // client transport address -> user
	users  map[string]int       // allocations per user
	total  int
	relays map[uint16]bool // relayed ports in use
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
	}
	if cfg.UDP != nil {
		sc.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: cfg.UDP, RelayAddressGenerator: gen, PermissionHandler: t.permit}}
	}
	if cfg.TCP != nil {
		sc.ListenerConfigs = []turn.ListenerConfig{{Listener: cfg.TCP, RelayAddressGenerator: gen, PermissionHandler: t.permit}}
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

// revokeGuest ends a guest's credentials early (its pairing window closed).
func (t *TURNServer) revokeGuest(user string) {
	t.mu.Lock()
	delete(t.guests, user)
	t.mu.Unlock()
}

func (t *TURNServer) mint(user string, until time.Time) TURNCreds {
	name := strconv.FormatInt(until.Unix(), 10) + ":" + user
	return TURNCreds{Username: name, Credential: t.credential(name), TTL: until.Sub(t.now()).Truncate(time.Second)}
}

func (t *TURNServer) credential(username string) string {
	mac := hmac.New(sha1.New, t.cfg.Key[:])
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// auth is pion's AuthHandler: the REST credential check, then the app's
// Authorize (or the guest list), on every authenticated request.
func (t *TURNServer) auth(ra *turn.RequestAttributes) (string, []byte, bool) {
	exp, user, ok := strings.Cut(ra.Username, ":")
	if !ok || user == "" {
		return "", nil, false
	}
	e, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || e < t.now().Unix() {
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
			t.cfg.Logf("turn: refused %s: %v", user, err)
			return "", nil, false
		}
	}
	if ra.SrcAddr != nil {
		t.rememberSrc(ra.SrcAddr.String(), user)
	}
	return user, turn.GenerateAuthKey(ra.Username, ra.Realm, t.credential(ra.Username)), true
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
	if t.cfg.AllowPeer != nil {
		return t.cfg.AllowPeer(user, ip)
	}
	relayed := ip == t.cfg.RelayIP
	if relayed && port != 0 {
		t.mu.Lock()
		relayed = t.relays[port]
		t.mu.Unlock()
	}
	if strings.HasPrefix(user, guestUserPrefix) {
		return relayed
	}
	if relayed {
		return true
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
	t.mu.Lock()
	switch {
	case t.total >= t.cfg.MaxTotal:
		t.mu.Unlock()
		return nil, nil, errTURNServerQuota
	case t.users[conf.UserID] >= t.cfg.MaxPerUser:
		t.mu.Unlock()
		return nil, nil, errTURNUserQuota
	}
	t.users[conf.UserID]++
	t.total++
	t.mu.Unlock()
	conn, addr, err := g.inner.AllocatePacketConn(conf)
	if err != nil {
		t.release(conf.UserID, 0)
		return nil, nil, err
	}
	port := addrPortOf(conn.LocalAddr()).Port()
	t.mu.Lock()
	t.relays[port] = true
	t.mu.Unlock()
	return &turnRelayConn{PacketConn: conn, t: t, user: conf.UserID, port: port}, addr, nil
}

func (g *turnRelayGen) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errTURNTCPRelay
}

func (g *turnRelayGen) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, errTURNTCPRelay
}

func (t *TURNServer) release(user string, port uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.users[user]--; t.users[user] <= 0 {
		delete(t.users, user)
	}
	t.total--
	if port != 0 {
		delete(t.relays, port)
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
	c.once.Do(func() { c.t.release(c.user, c.port) })
	return c.PacketConn.Close()
}
