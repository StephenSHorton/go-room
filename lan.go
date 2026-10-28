package room

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// The LAN carrier: sealed UDP datagrams on one fixed port, sent to the
// directed broadcast address of each local private subnet for everyone, and
// unicast to a member once an authentic envelope from it has been heard.
// Every datagram is
//
//	"GR1" || tag(8) || sealed payload (nonce(24) || secretbox)
//
// where tag = SHA-256("go-room/lan/1" || topic || u64(unix seconds / 300))[:8].
// The tag picks the room without trying every key, and it changes every five
// minutes, so a listener can't follow one device from network to network by
// a fixed value. Receivers accept the previous, current and next window, so
// a sender whose clock is ahead (within the envelope age limit) isn't lost
// at the end of each window.

// LAN limits and defaults.
const (
	MaxLANDatagram = 8 << 10 // bytes, header included
	DefaultLANRate = 200     // datagrams opened per second
	lanMagic       = "GR1"
	lanTagLen      = 8
	lanHeader      = len(lanMagic) + lanTagLen
	lanWindow      = 300 // seconds per tag window
	lanAddrCap     = 256 // remembered member addresses per room
)

// ErrTooBigDatagram is Publish's error for a payload that doesn't fit one
// LAN datagram.
var ErrTooBigDatagram = errors.New("room: envelope too big for a LAN datagram")

// LANConfig sets up the LAN carrier.
type LANConfig struct {
	// Port is the fixed UDP port every device uses (Irori: 38419).
	Port int
	// Conn, when set, is used instead of binding the wildcard address on
	// Port (tests: a MemLAN conn or a 127.0.0.1 socket). The LAN closes it.
	Conn net.PacketConn
	// Targets is where envelopes for everyone go. nil: the directed
	// broadcast address of each up private IPv4 interface on Port, skipping
	// networks on the Public firewall profile on Windows.
	Targets func() []netip.AddrPort
	// MaxRate caps datagrams opened per second (default DefaultLANRate); the
	// rest are dropped unopened.
	MaxRate int
	// Now is the clock for the tag window (tests).
	Now func() time.Time
	// Logf, when set, gets diagnostics (never payloads).
	Logf func(format string, args ...any)
}

// LAN is one UDP socket carrying every room opened on it.
type LAN struct {
	conn    net.PacketConn
	port    int
	targets func() []netip.AddrPort
	maxRate int
	now     func() time.Time
	logf    func(string, ...any)
	own     func(netip.Addr) bool

	mu      sync.Mutex
	legs    map[string][]*lanLeg // by topic
	tagW    int64                // window the tag table was built for
	tags    map[[lanTagLen]byte][]string
	rateAt  int64
	rateN   int
	closed  bool
	readEnd chan struct{}
}

// OpenLAN opens the LAN carrier's socket and starts reading.
func OpenLAN(cfg LANConfig) (*LAN, error) {
	l := &LAN{
		conn:    cfg.Conn,
		port:    cfg.Port,
		targets: cfg.Targets,
		maxRate: cfg.MaxRate,
		now:     cfg.Now,
		logf:    cfg.Logf,
		legs:    map[string][]*lanLeg{},
		tagW:    -1,
		readEnd: make(chan struct{}),
	}
	if l.maxRate <= 0 {
		l.maxRate = DefaultLANRate
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.logf == nil {
		l.logf = func(string, ...any) {}
	}
	if l.conn == nil {
		if cfg.Port <= 0 || cfg.Port > 65535 {
			return nil, errors.New("room: LAN port out of range")
		}
		// Broadcasts reach only a wildcard bind on Windows; Go sets
		// SO_BROADCAST on every UDP socket.
		c, err := net.ListenPacket("udp4", ":"+strconv.Itoa(cfg.Port))
		if err != nil {
			return nil, err
		}
		l.conn = c
		own := newOwnIPs()
		l.own = own.has
	}
	if l.targets == nil {
		l.targets = func() []netip.AddrPort { return broadcastTargets(l.port) }
	}
	go l.read()
	return l, nil
}

// Carrier returns the LAN as a Carrier.
func (l *LAN) Carrier() Carrier { return lanCarrier{l} }

// Close stops reading and closes the socket and every leg.
func (l *LAN) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.legs = map[string][]*lanLeg{}
	l.mu.Unlock()
	_ = l.conn.Close()
	<-l.readEnd
}

// LocalAddr is the socket's address.
func (l *LAN) LocalAddr() net.Addr { return l.conn.LocalAddr() }

// Targets is where an envelope for everyone goes right now. Empty means
// the LAN carrier sends nothing: no private network, or (Windows) every
// one is on the Public profile.
func (l *LAN) Targets() []netip.AddrPort { return l.targets() }

// OnPublicNetwork reports whether ip is this machine's address on a
// network Windows has on the Public firewall profile (always false on
// other systems), where the LAN carrier stays silent and Windows Firewall
// blocks what a server listens for.
func OnPublicNetwork(ip netip.Addr) bool {
	public := publicInterfaces()
	for _, s := range LocalSubnets() {
		if s.Prefix.Addr() == ip.Unmap() {
			return public[s.Index]
		}
	}
	return false
}

type lanCarrier struct{ l *LAN }

func (c lanCarrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (Leg, error) {
	l := c.l
	lg := &lanLeg{l: l, topic: topic, deliver: deliver, addrs: map[string]netip.AddrPort{}}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	l.legs[topic] = append(l.legs[topic], lg)
	l.tagW = -1 // rebuild the tag table
	l.mu.Unlock()
	if up != nil {
		go up()
	}
	return lg, nil
}

// lanTag is a topic's tag for one window.
func lanTag(topic string, window int64) [lanTagLen]byte {
	h := sha256.New()
	h.Write([]byte("go-room/lan/1"))
	h.Write([]byte(topic))
	var w [8]byte
	binary.BigEndian.PutUint64(w[:], uint64(window))
	h.Write(w[:])
	var t [lanTagLen]byte
	copy(t[:], h.Sum(nil))
	return t
}

func (l *LAN) window() int64 { return l.now().Unix() / lanWindow }

// topicsFor returns the open topics a tag names, in the previous, current
// or next window. Called with l.mu held.
func (l *LAN) topicsFor(tag [lanTagLen]byte) []string {
	w := l.window()
	if w != l.tagW {
		l.tags = map[[lanTagLen]byte][]string{}
		for topic := range l.legs {
			for _, ww := range []int64{w, w - 1, w + 1} {
				t := lanTag(topic, ww)
				l.tags[t] = append(l.tags[t], topic)
			}
		}
		l.tagW = w
	}
	return l.tags[tag]
}

func (l *LAN) read() {
	defer close(l.readEnd)
	buf := make([]byte, MaxLANDatagram+1)
	for {
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports an ICMP port unreachable from an earlier send
			// as a read error on UDP sockets; keep reading.
			continue
		}
		if n < lanHeader+24 || n > MaxLANDatagram || string(buf[:len(lanMagic)]) != lanMagic {
			continue
		}
		from := addrPortOf(addr)
		if l.isSelf(from) {
			continue
		}
		var tag [lanTagLen]byte
		copy(tag[:], buf[len(lanMagic):lanHeader])
		l.mu.Lock()
		topics := l.topicsFor(tag)
		if len(topics) == 0 || !l.takeRate() {
			l.mu.Unlock()
			continue
		}
		var legs []*lanLeg
		for _, t := range topics {
			legs = append(legs, l.legs[t]...)
		}
		l.mu.Unlock()
		payload := append([]byte(nil), buf[lanHeader:n]...)
		for _, lg := range legs {
			lg.deliver(payload, from)
		}
	}
}

// takeRate spends one of this second's opens. Called with l.mu held.
func (l *LAN) takeRate() bool {
	sec := l.now().Unix()
	if sec != l.rateAt {
		l.rateAt, l.rateN = sec, 0
	}
	if l.rateN >= l.maxRate {
		return false
	}
	l.rateN++
	return true
}

// isSelf reports whether a datagram came from this socket (a broadcast
// comes back to its sender).
func (l *LAN) isSelf(from netip.AddrPort) bool {
	local := addrPortOf(l.conn.LocalAddr())
	if from == local {
		return true
	}
	return l.own != nil && local.Addr().IsUnspecified() && from.Port() == local.Port() && l.own(from.Addr())
}

func addrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	case interface{ AddrPort() netip.AddrPort }:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if a == nil {
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

func (l *LAN) send(dst netip.AddrPort, dgram []byte) error {
	_, err := l.conn.WriteTo(dgram, net.UDPAddrFromAddrPort(dst))
	return err
}

// lanLeg is one topic on the LAN.
type lanLeg struct {
	l       *LAN
	topic   string
	deliver func([]byte, netip.AddrPort)

	mu     sync.Mutex
	addrs  map[string]netip.AddrPort // member -> where its last authentic envelope came from
	closed bool
}

func (g *lanLeg) Publish(to string, payload []byte) error {
	if len(payload)+lanHeader > MaxLANDatagram {
		return ErrTooBigDatagram
	}
	if !g.Up() {
		return ErrClosed
	}
	tag := lanTag(g.topic, g.l.window())
	dgram := make([]byte, 0, lanHeader+len(payload))
	dgram = append(dgram, lanMagic...)
	dgram = append(dgram, tag[:]...)
	dgram = append(dgram, payload...)
	if to != "" {
		g.mu.Lock()
		a, ok := g.addrs[to]
		g.mu.Unlock()
		if ok {
			return g.l.send(a, dgram)
		}
	}
	targets := g.l.targets()
	if len(targets) == 0 {
		return ErrNotConnected
	}
	var last error
	sent := 0
	for _, t := range targets {
		if err := g.l.send(t, dgram); err != nil {
			last = err
			continue
		}
		sent++
	}
	if sent == 0 {
		return last
	}
	return nil
}

func (g *lanLeg) Seen(member string, from netip.AddrPort) {
	if !from.IsValid() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.addrs[member]; !ok && len(g.addrs) >= lanAddrCap {
		for k := range g.addrs {
			delete(g.addrs, k)
			break
		}
	}
	g.addrs[member] = from
}

func (g *lanLeg) Up() bool {
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return false
	}
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	return !g.l.closed
}

func (g *lanLeg) Close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	g.mu.Unlock()
	l := g.l
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.legs[g.topic]
	for i, x := range list {
		if x == g {
			l.legs[g.topic] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(l.legs[g.topic]) == 0 {
		delete(l.legs, g.topic)
	}
	l.tagW = -1
}

// --- interfaces ---------------------------------------------------------

// ownIPs is this host's interface addresses, refreshed now and then, to drop
// our own broadcasts.
type ownIPs struct {
	mu   sync.Mutex
	at   time.Time
	addr map[netip.Addr]bool
}

func newOwnIPs() *ownIPs { return &ownIPs{} }

func (o *ownIPs) has(a netip.Addr) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.addr == nil || time.Since(o.at) > 30*time.Second {
		o.addr = map[netip.Addr]bool{}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, ia := range addrs {
				if p, err := netip.ParsePrefix(ia.String()); err == nil {
					o.addr[p.Addr().Unmap()] = true
				}
			}
		}
		o.at = time.Now()
	}
	return o.addr[a]
}

// LocalSubnet is one up IPv4 interface address with a private address.
type LocalSubnet struct {
	Index  int          // interface index
	Prefix netip.Prefix // address and mask, e.g. 192.168.1.20/24
}

// LocalSubnets lists the up, non-loopback interfaces' private IPv4
// addresses (RFC 1918). The LAN carrier broadcasts to these; the TURN
// server's default peer filter allows them.
func LocalSubnets() []LocalSubnet {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []LocalSubnet
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			ones, bits := ipn.Mask.Size()
			if !ip.Is4() || !ip.IsPrivate() || bits != 32 || ones < 8 || ones > 30 {
				continue
			}
			out = append(out, LocalSubnet{Index: ifc.Index, Prefix: netip.PrefixFrom(ip, ones)})
		}
	}
	return out
}

// directedBroadcast is the subnet's broadcast address (192.168.1.255 for
// 192.168.1.20/24).
func directedBroadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	v := binary.BigEndian.Uint32(a[:])
	v |= ^uint32(0) >> p.Bits()
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

// broadcastTargets is the default Targets: each private subnet's directed
// broadcast address (not 255.255.255.255, which Windows sends out of one
// interface only), minus networks on the Public profile.
func broadcastTargets(port int) []netip.AddrPort {
	public := publicInterfaces()
	seen := map[netip.Addr]bool{}
	var out []netip.AddrPort
	for _, s := range LocalSubnets() {
		if public[s.Index] {
			continue
		}
		b := directedBroadcast(s.Prefix)
		if !seen[b] {
			seen[b] = true
			out = append(out, netip.AddrPortFrom(b, uint16(port)))
		}
	}
	return out
}
