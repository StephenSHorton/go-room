package room

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// HubDialConfig sets up a connection to a hub.
type HubDialConfig struct {
	// Self is this member's device id (unused for a guest).
	Self string
	// Identity signs the hello; nil makes this a guest.
	Identity *Identity
	// GuestTopic is a guest's one topic (its pairing room).
	GuestTopic string
	// Addrs lists host:port addresses for the hub. They are dialed in
	// parallel and the first to complete the handshake wins; it is read
	// again on every reconnect.
	Addrs func() []string
	// Expect checks the hub's welcome: the server device's id and the key
	// it proved. Required for members (Irori: a certified, unrevoked
	// device); optional for a guest, which records the key instead.
	Expect func(id string, pub ed25519.PublicKey) error
	// Dial opens the TCP connection (default net.Dialer; tests: 127.0.0.1).
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// TURNURIs gives the ICE URLs for TURN credentials from the hub reached
	// at addr. nil: stun:, turn:?transport=udp and turn:?transport=tcp at
	// addr itself, since a home server's TURN shares the hub's port number.
	TURNURIs func(addr string) []string
	// Logf, when set, gets diagnostics (never payloads or credentials).
	Logf func(format string, args ...any)
}

// HubClient is a connection to a hub that reconnects by itself, 1 s, 2 s,
// 4 s ... up to 60 s apart.
type HubClient struct {
	cfg HubDialConfig

	mu      sync.Mutex
	tc      *tls.Conn
	addr    string
	srvID   string
	srvPub  ed25519.PublicKey
	upCh    chan struct{} // closed while connected
	legs    map[string][]*hubClientLeg
	guests  map[string]time.Time // guest topics this member opened, until
	pending []chan hubTURNBody
	closed  bool
	quit    chan struct{}
	done    chan struct{}
	wmu     sync.Mutex
}

// errNoExpect is logged when a member has no Expect; it never connects.
var errNoExpect = errors.New("room: HubDialConfig.Expect is required for a member")

// DialHub starts connecting to the hub in the background.
func DialHub(cfg HubDialConfig) *HubClient {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Dial == nil {
		d := &net.Dialer{}
		cfg.Dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp", addr) }
	}
	c := &HubClient{
		cfg:    cfg,
		upCh:   make(chan struct{}),
		legs:   map[string][]*hubClientLeg{},
		guests: map[string]time.Time{},
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.loop()
	return c
}

// Up reports whether the hub connection is up.
func (c *HubClient) Up() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tc != nil
}

// Addr is the address that completed the handshake ("" while down).
func (c *HubClient) Addr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addr
}

// Server is the hub's device id and key from its last welcome.
func (c *HubClient) Server() (id string, pub ed25519.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.srvID, c.srvPub
}

// Close disconnects and stops reconnecting.
func (c *HubClient) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.quit)
	tc := c.tc
	c.mu.Unlock()
	if tc != nil {
		_ = tc.Close()
	}
	<-c.done
}

func (c *HubClient) loop() {
	defer close(c.done)
	if c.cfg.Identity != nil && c.cfg.Expect == nil {
		c.cfg.Logf("hub: %v", errNoExpect)
		return
	}
	backoff := hubRetryMin
	for {
		tc, addr, w, err := c.dialAll()
		if err == nil {
			backoff = hubRetryMin
			c.run(tc, addr, w)
		} else {
			c.cfg.Logf("hub: %v", err)
		}
		select {
		case <-c.quit:
			return
		case <-time.After(backoff):
		}
		if err != nil {
			backoff = min(backoff*2, hubRetryMax)
		}
	}
}

type hubDialResult struct {
	tc   *tls.Conn
	addr string
	w    hubWelcome
	err  error
}

// dialAll dials every address at once and keeps the first handshake.
func (c *HubClient) dialAll() (*tls.Conn, string, hubWelcome, error) {
	var addrs []string
	seen := map[string]bool{}
	if c.cfg.Addrs != nil {
		for _, a := range c.cfg.Addrs() {
			if a != "" && !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		return nil, "", hubWelcome{}, errors.New("no address for the hub")
	}
	ctx, cancel := context.WithTimeout(context.Background(), hubDialTimeout)
	defer cancel()
	go func() {
		select {
		case <-c.quit:
			cancel()
		case <-ctx.Done():
		}
	}()
	results := make(chan hubDialResult, len(addrs))
	for _, a := range addrs {
		go func(a string) {
			tc, w, err := c.dialOne(ctx, a)
			results <- hubDialResult{tc: tc, addr: a, w: w, err: err}
		}(a)
	}
	var win *hubDialResult
	var last error
	for range addrs {
		r := <-results
		if r.err != nil {
			last = r.err
			continue
		}
		if win == nil {
			win = &r
			cancel() // the others give up; their conns are closed below
			continue
		}
		_ = r.tc.Close()
	}
	if win == nil {
		return nil, "", hubWelcome{}, last
	}
	return win.tc, win.addr, win.w, nil
}

func (c *HubClient) dialOne(ctx context.Context, addr string) (*tls.Conn, hubWelcome, error) {
	var w hubWelcome
	raw, err := c.cfg.Dial(ctx, addr)
	if err != nil {
		return nil, w, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	tc := tls.Client(raw, &tls.Config{
		// Nothing pins the hub's certificate; both ends sign the session's
		// exporter instead (below).
		InsecureSkipVerify: true, //nolint:gosec // see above
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{HubALPN},
	})
	fail := func(err error) (*tls.Conn, hubWelcome, error) {
		_ = raw.Close()
		return nil, w, err
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(err)
	}
	x, err := hubExporter(tc.ConnectionState())
	if err != nil {
		return fail(err)
	}
	hello := hubHello{V: 1}
	if id := c.cfg.Identity; id != nil {
		hello.ID, hello.Pub = c.cfg.Self, id.Pub
		hello.Sig = id.Sign(hubSigPayload(hubClientContext, x, c.cfg.Self))
	} else {
		hello.Guest, hello.Topic = true, c.cfg.GuestTopic
	}
	if err := writeFrame(tc, frameHello, marshal(hello)); err != nil {
		return fail(err)
	}
	typ, body, err := readFrame(tc, 4<<10)
	if err != nil {
		return fail(errors.New("hub closed the connection (refused, or not a hub)"))
	}
	if typ != frameWelcome || parseJSON(body, &w) != nil || w.V != 1 {
		return fail(errHubFrame)
	}
	if !verifyHubSig(hubServerContext, x, w.ID, w.Pub, w.Sig) {
		return fail(errors.New("hub's welcome signature doesn't verify"))
	}
	if c.cfg.Expect != nil {
		if err := c.cfg.Expect(w.ID, ed25519.PublicKey(w.Pub)); err != nil {
			return fail(err)
		}
	}
	if !stop() {
		return fail(ctx.Err())
	}
	_ = raw.SetDeadline(time.Time{})
	return tc, w, nil
}

// run serves one connection until it drops.
func (c *HubClient) run(tc *tls.Conn, addr string, w hubWelcome) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = tc.Close()
		return
	}
	c.tc, c.addr, c.srvID, c.srvPub = tc, addr, w.ID, ed25519.PublicKey(w.Pub)
	var topics []string
	var ups []func()
	for t, legs := range c.legs {
		topics = append(topics, t)
		for _, l := range legs {
			if l.up != nil {
				ups = append(ups, l.up)
			}
		}
	}
	now := time.Now()
	guests := map[string]time.Duration{}
	for t, until := range c.guests {
		if left := until.Sub(now); left > 0 {
			guests[t] = left
		} else {
			delete(c.guests, t)
		}
	}
	close(c.upCh)
	c.mu.Unlock()
	c.cfg.Logf("hub: connected to %s at %s", w.ID, addr)

	for t, left := range guests {
		_ = c.write(frameGuestOpen, marshal(hubGuestBody{Topic: t, TTLMs: left.Milliseconds()}))
	}
	for _, t := range topics {
		_ = c.write(frameSub, []byte(t))
	}
	for _, up := range ups {
		go up()
	}

	pingDone := make(chan struct{})
	go func() {
		t := time.NewTicker(hubPingEvery)
		defer t.Stop()
		for {
			select {
			case <-pingDone:
				return
			case <-t.C:
				if c.write(framePing, nil) != nil {
					return
				}
			}
		}
	}()
	for {
		_ = tc.SetReadDeadline(time.Now().Add(hubIdleTimeout))
		typ, body, err := readFrame(tc, MaxHubFrame)
		if err != nil {
			break
		}
		switch typ {
		case frameMsg:
			topic, payload, ok := splitTopicBody(body)
			if !ok {
				continue
			}
			c.mu.Lock()
			legs := append([]*hubClientLeg(nil), c.legs[topic]...)
			c.mu.Unlock()
			for _, l := range legs {
				l.q.push(payload)
			}
		case frameTURNCreds:
			var b hubTURNBody
			_ = parseJSON(body, &b)
			c.mu.Lock()
			if len(c.pending) > 0 {
				ch := c.pending[0]
				c.pending = c.pending[1:]
				ch <- b
			}
			c.mu.Unlock()
		case framePing:
			_ = c.write(framePong, nil)
		case frameErr:
			var e hubErrBody
			_ = parseJSON(body, &e)
			c.cfg.Logf("hub: %s closed the connection: %s", w.ID, e.Reason)
		}
	}
	close(pingDone)
	_ = tc.Close()
	c.mu.Lock()
	c.tc, c.addr = nil, ""
	c.upCh = make(chan struct{})
	for _, ch := range c.pending {
		close(ch)
	}
	c.pending = nil
	c.mu.Unlock()
	c.cfg.Logf("hub: disconnected from %s", addr)
}

func (c *HubClient) write(typ byte, body []byte) error {
	c.mu.Lock()
	tc := c.tc
	c.mu.Unlock()
	if tc == nil {
		return ErrNotConnected
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = tc.SetWriteDeadline(time.Now().Add(hubWriteTimeout))
	if err := writeFrame(tc, typ, body); err != nil {
		_ = tc.Close()
		return err
	}
	return nil
}

// waitUp waits for the connection to be up.
func (c *HubClient) waitUp(ctx context.Context) error {
	c.mu.Lock()
	ch, closed := c.upCh, c.closed
	c.mu.Unlock()
	if closed {
		return ErrClosed
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.quit:
		return ErrClosed
	}
}

// OpenGuest asks the hub to admit guests to topic (a pairing room) for ttl
// (at most MaxGuestTTL). It waits for the connection up to ctx, and is sent
// again on every reconnect until ttl runs out or CloseGuest.
func (c *HubClient) OpenGuest(ctx context.Context, topic string, ttl time.Duration) error {
	if ttl <= 0 || ttl > MaxGuestTTL {
		ttl = MaxGuestTTL
	}
	if c.cfg.Identity == nil {
		return errors.New("room: a guest can't open guest topics")
	}
	if err := c.waitUp(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.guests[topic] = time.Now().Add(ttl)
	c.mu.Unlock()
	return c.write(frameGuestOpen, marshal(hubGuestBody{Topic: topic, TTLMs: ttl.Milliseconds()}))
}

// CloseGuest closes a guest topic this member opened.
func (c *HubClient) CloseGuest(topic string) {
	c.mu.Lock()
	delete(c.guests, topic)
	c.mu.Unlock()
	_ = c.write(frameGuestClose, marshal(hubGuestBody{Topic: topic}))
}

// TURN asks the hub for TURN credentials for this device (a guest's are
// narrower and last only while its topic is open). Pass it as
// RelayConfig.Fetch.
func (c *HubClient) TURN(ctx context.Context) (TURNCreds, error) {
	if err := c.waitUp(ctx); err != nil {
		return TURNCreds{}, err
	}
	ch := make(chan hubTURNBody, 1)
	c.mu.Lock()
	if c.tc == nil {
		c.mu.Unlock()
		return TURNCreds{}, ErrNotConnected
	}
	c.pending = append(c.pending, ch)
	addr := c.addr
	c.mu.Unlock()
	if err := c.write(frameTURNGet, []byte("{}")); err != nil {
		return TURNCreds{}, err
	}
	select {
	case b, ok := <-ch:
		if !ok {
			return TURNCreds{}, ErrNotConnected
		}
		if b.Username == "" || b.Credential == "" {
			return TURNCreds{}, errors.New("room: the hub has no relay")
		}
		uris := defaultTURNURIs(addr)
		if c.cfg.TURNURIs != nil {
			uris = c.cfg.TURNURIs(addr)
		}
		return TURNCreds{Username: b.Username, Credential: b.Credential, TTL: time.Duration(b.TTLS) * time.Second, URIs: uris}, nil
	case <-ctx.Done():
		return TURNCreds{}, ctx.Err()
	}
}

func defaultTURNURIs(addr string) []string {
	return []string{"stun:" + addr, "turn:" + addr + "?transport=udp", "turn:" + addr + "?transport=tcp"}
}

// Carrier is the hub connection as a Carrier.
func (c *HubClient) Carrier() Carrier { return hubClientCarrier{c} }

type hubClientCarrier struct{ c *HubClient }

func (cc hubClientCarrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (Leg, error) {
	c := cc.c
	if topic == "" || len(topic) > 255 {
		return nil, errors.New("room: hub topic must be 1-255 bytes")
	}
	l := &hubClientLeg{c: c, topic: topic, up: up, q: newQueue(func(p []byte) { deliver(p, netip.AddrPort{}) })}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		l.q.stop()
		return nil, ErrClosed
	}
	first := len(c.legs[topic]) == 0
	c.legs[topic] = append(c.legs[topic], l)
	connected := c.tc != nil
	c.mu.Unlock()
	if connected {
		if first {
			_ = c.write(frameSub, []byte(topic))
		}
		if up != nil {
			go up()
		}
	}
	return l, nil
}

type hubClientLeg struct {
	c      *HubClient
	topic  string
	up     func()
	q      *queue
	mu     sync.Mutex
	closed bool
}

func (l *hubClientLeg) Publish(_ string, payload []byte) error {
	body, err := topicBody(l.topic, payload)
	if err != nil {
		return err
	}
	if len(body)+1 > MaxHubFrame {
		return ErrTooBig
	}
	return l.c.write(framePub, body)
}

func (l *hubClientLeg) Seen(string, netip.AddrPort) {}

func (l *hubClientLeg) Up() bool {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	return !closed && l.c.Up()
}

func (l *hubClientLeg) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	c := l.c
	c.mu.Lock()
	list := c.legs[l.topic]
	for i, x := range list {
		if x == l {
			c.legs[l.topic] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	last := len(c.legs[l.topic]) == 0
	if last {
		delete(c.legs, l.topic)
	}
	c.mu.Unlock()
	if last {
		_ = c.write(frameUnsub, []byte(l.topic))
	}
	l.q.stop()
}
