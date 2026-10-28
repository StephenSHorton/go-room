package room

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// Envelope types Mesh sends and owns.
const (
	MsgWant   = "rtc.want"   // to the offerer: please offer to me
	MsgOffer  = "rtc.offer"  // offerer → answerer: session, sdp
	MsgAnswer = "rtc.answer" // answerer → offerer: session, sdp
	MsgBye    = "rtc.bye"    // either way: session, reason
)

// Defaults for Config's zero values.
const (
	DefaultMaxMessage     = 4 << 20
	DefaultMaxStreams     = 4
	DefaultAuthTimeout    = 10 * time.Second
	DefaultConnectTimeout = 30 * time.Second
	gatherCap             = 4 * time.Second // send what we have; host candidates come first
	wantEvery             = time.Second     // at most one rtc.want per peer per this
	staleUp               = 10 * time.Second
	backoffMin            = time.Second
	backoffMax            = 60 * time.Second
)

// Identity is this member's long-term ed25519 key, as a public key and a
// signing function, so the private key can stay wherever the app keeps it.
type Identity struct {
	Pub  ed25519.PublicKey
	Sign func(msg []byte) []byte
}

// KeyIdentity is an Identity for a private key held in memory.
func KeyIdentity(priv ed25519.PrivateKey) Identity {
	return Identity{
		Pub:  priv.Public().(ed25519.PublicKey),
		Sign: func(msg []byte) []byte { return ed25519.Sign(priv, msg) },
	}
}

// Config sets up a Mesh.
type Config struct {
	// Self is this member's id; it must match the Signaler's.
	Self string
	// Identity signs this side of each connection's auth handshake.
	Identity Identity
	// Accept is the app's decision on a peer, called once both auth
	// signatures verified: pub is the key the peer proved it holds. A nil
	// return lets the peer up. Required: during a pairing it may accept any
	// key (and record it); afterwards it should check pub against what it
	// knows about peer.
	Accept func(peer string, pub ed25519.PublicKey) error
	// Allow is asked before any PeerConnection is made for peer, for a local
	// Connect, an incoming offer or an incoming want. nil allows everyone in
	// the room.
	Allow func(peer string) bool
	// Offerer reports whether this side makes the offer to peer. Both sides
	// must agree. nil: the lower id offers.
	Offerer func(peer string) bool
	// ICE is read for each new connection (Relay.Servers). nil means
	// DefaultSTUN; a func returning nil means no servers (loopback tests).
	ICE func() []ICEServer
	// Tune adjusts the pion SettingEngine after go-room's own settings
	// (tests: LoopbackOnly()).
	Tune func(*webrtc.SettingEngine)
	// MaxMessage caps one Channel message, both ways (default 4 MiB).
	MaxMessage int
	// MaxStreams caps concurrent streams per peer in each direction (default
	// 4). OpenStream waits for a free slot; an incoming stream over the cap is
	// closed at once.
	MaxStreams int
	// AuthTimeout bounds the handshake once the data channel is open
	// (default 10 s); ConnectTimeout bounds a whole attempt (default 30 s).
	AuthTimeout    time.Duration
	ConnectTimeout time.Duration
	// Logf, when set, gets diagnostics (never secrets).
	Logf func(format string, args ...any)
}

// Mesh makes and keeps authenticated connections to other members of one
// room. It owns the rtc.* envelopes on its Signaler; use one Mesh per
// Signaler. Closing the Mesh doesn't close the Signaler.
type Mesh struct {
	sig       Signaler
	cfg       Config
	api       *webrtc.API
	topicHash [32]byte

	mu      sync.Mutex
	peers   map[string]*Peer // the current attempt or connection per peer
	retry   map[string]*retryState
	wantAt  map[string]time.Time
	onPeer  func(*Peer)
	onDown  func(string, error)
	closed  bool
	pcs     sync.WaitGroup
	evMu    sync.Mutex
	events  []func()
	evWake  chan struct{}
	evDone  chan struct{}
	evClose chan struct{}
}

type retryState struct {
	backoff time.Duration
	next    time.Time
	timer   *time.Timer
}

// NewMesh starts handling rtc.* envelopes on sig.
func NewMesh(sig Signaler, cfg Config) (*Mesh, error) {
	if sig == nil || sig.core() == nil {
		return nil, errors.New("room: no signaler")
	}
	if cfg.Self == "" {
		cfg.Self = sig.Self()
	}
	if cfg.Self != sig.Self() {
		return nil, errors.New("room: Config.Self doesn't match the signaler")
	}
	if len(cfg.Self) > 255 {
		return nil, errors.New("room: member id too long")
	}
	if len(cfg.Identity.Pub) != ed25519.PublicKeySize || cfg.Identity.Sign == nil {
		return nil, errors.New("room: Config.Identity needs an ed25519 public key and a Sign function")
	}
	if cfg.Accept == nil {
		return nil, errors.New("room: Config.Accept is required")
	}
	if cfg.MaxMessage <= 0 {
		cfg.MaxMessage = DefaultMaxMessage
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	if cfg.AuthTimeout <= 0 {
		cfg.AuthTimeout = DefaultAuthTimeout
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	se.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	// No mDNS: there is no browser to hide addresses from, and its multicast
	// socket would be one more listener on a real interface.
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	if cfg.Tune != nil {
		cfg.Tune(&se)
	}
	m := &Mesh{
		sig:     sig,
		cfg:     cfg,
		api:     webrtc.NewAPI(webrtc.WithSettingEngine(se)),
		peers:   map[string]*Peer{},
		retry:   map[string]*retryState{},
		wantAt:  map[string]time.Time{},
		evWake:  make(chan struct{}, 1),
		evDone:  make(chan struct{}),
		evClose: make(chan struct{}),
	}
	m.topicHash = sha256.Sum256([]byte(sig.Topic()))
	go m.eventLoop()
	sig.core().setRTC(m.handle)
	return m, nil
}

// OnPeer sets the handler for a peer coming up: both auth signatures
// verified and Accept passed on both sides. Set it before Connect.
func (m *Mesh) OnPeer(fn func(*Peer)) {
	m.mu.Lock()
	m.onPeer = fn
	m.mu.Unlock()
}

// OnPeerDown sets the handler for an up peer going away, with why.
func (m *Mesh) OnPeerDown(fn func(peer string, err error)) {
	m.mu.Lock()
	m.onDown = fn
	m.mu.Unlock()
}

// Peer returns the connected peer with id, or nil.
func (m *Mesh) Peer(id string) *Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.peers[id]; p != nil && p.isUp() {
		return p
	}
	return nil
}

// Peers returns every connected peer.
func (m *Mesh) Peers() []*Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Peer
	for _, p := range m.peers {
		if p.isUp() {
			out = append(out, p)
		}
	}
	return out
}

func (m *Mesh) isOfferer(peer string) bool {
	if m.cfg.Offerer != nil {
		return m.cfg.Offerer(peer)
	}
	return m.cfg.Self < peer
}

func (m *Mesh) allowed(peer string) bool {
	return peer != "" && peer != m.cfg.Self && len(peer) <= 255 && (m.cfg.Allow == nil || m.cfg.Allow(peer))
}

// Connect makes sure there is (or soon will be) a connection to peer: it
// offers if this side is the offerer, and asks peer to offer (rtc.want)
// otherwise. It is idempotent while an attempt is running or the peer is up,
// and after a failed attempt it waits out a backoff (1 s doubling to 60 s)
// before offering again. Call it whenever peer is seen in the room.
func (m *Mesh) Connect(peer string) {
	if !m.allowed(peer) {
		return
	}
	offerer := m.isOfferer(peer)
	m.mu.Lock()
	if m.closed || m.peers[peer] != nil {
		m.mu.Unlock()
		return
	}
	if !offerer {
		now := time.Now()
		if now.Sub(m.wantAt[peer]) < wantEvery {
			m.mu.Unlock()
			return
		}
		m.wantAt[peer] = now
		m.mu.Unlock()
		if err := m.sig.Send(peer, MsgWant, struct{}{}); err != nil {
			m.cfg.Logf("room: want to %s: %v", peer, err)
		}
		return
	}
	if r := m.retry[peer]; r != nil {
		if wait := time.Until(r.next); wait > 0 {
			if r.timer == nil {
				r.timer = time.AfterFunc(wait, func() {
					m.mu.Lock()
					if rr := m.retry[peer]; rr == r {
						r.timer = nil
					}
					m.mu.Unlock()
					m.Connect(peer)
				})
			}
			m.mu.Unlock()
			return
		}
	}
	p := m.newPeerLocked(peer, randHex(8), true)
	m.mu.Unlock()
	go m.offer(p)
}

func (m *Mesh) newPeerLocked(id, session string, offerer bool) *Peer {
	p := &Peer{
		m: m, id: id, session: session, offerer: offerer,
		up: make(chan struct{}), done: make(chan struct{}),
		outSem:  make(chan struct{}, m.cfg.MaxStreams),
		streams: map[*Stream]struct{}{},
	}
	m.peers[id] = p
	m.pcs.Add(1)
	p.timer = time.AfterFunc(m.cfg.ConnectTimeout, func() {
		if !p.isUp() {
			p.close(fmt.Errorf("room: no connection to %s within %v", id, m.cfg.ConnectTimeout), true, "timeout")
		}
	})
	return p
}

type sdpBody struct {
	Session string `json:"session"`
	SDP     string `json:"sdp"`
}

type byeBody struct {
	Session string `json:"session"`
	Reason  string `json:"reason,omitempty"`
}

// offer runs one offer: a fresh PeerConnection, all candidates gathered (4 s
// cap), the SDP sent.
func (m *Mesh) offer(p *Peer) {
	if err := p.setup(); err != nil {
		p.close(err, false, "")
		return
	}
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		p.close(err, false, "")
		return
	}
	sdp, err := p.gather(offer)
	if err != nil {
		p.close(err, false, "")
		return
	}
	if err := m.sig.Send(p.id, MsgOffer, sdpBody{Session: p.session, SDP: sdp}); err != nil {
		p.close(fmt.Errorf("room: sending the offer: %w", err), false, "")
	}
}

// handle takes every rtc.* envelope from the signaler. Anything slow runs on
// its own goroutine, so the signaler keeps delivering.
func (m *Mesh) handle(env Envelope) {
	peer := env.From
	switch env.Type {
	case MsgWant:
		if !m.allowed(peer) || !m.isOfferer(peer) {
			return
		}
		m.mu.Lock()
		p := m.peers[peer]
		m.mu.Unlock()
		if p != nil && p.isUp() && time.Since(p.upAt()) > staleUp {
			// The other side has no connection to us (it only asks when it
			// has none), so this one is dead though ICE hasn't noticed yet.
			p.close(errors.New("room: peer asked for a new connection"), false, "")
		}
		m.Connect(peer)
	case MsgOffer:
		b, err := Decode[sdpBody](env)
		if err != nil || b.Session == "" || b.SDP == "" || !m.allowed(peer) {
			return
		}
		if m.isOfferer(peer) {
			// Two offerers would cross; this side's offer is the one.
			go m.Connect(peer)
			return
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return
		}
		old := m.peers[peer]
		if old != nil && old.session == b.Session {
			m.mu.Unlock()
			return
		}
		if old != nil {
			delete(m.peers, peer)
		}
		p := m.newPeerLocked(peer, b.Session, false)
		m.mu.Unlock()
		if old != nil {
			old.close(errors.New("room: replaced by a new connection"), false, "")
		}
		go m.answer(p, b.SDP)
	case MsgAnswer:
		b, err := Decode[sdpBody](env)
		if err != nil || b.Session == "" {
			return
		}
		m.mu.Lock()
		p := m.peers[peer]
		m.mu.Unlock()
		if p == nil || !p.offerer || p.session != b.Session {
			return
		}
		go p.setAnswer(b.SDP)
	case MsgBye:
		b, err := Decode[byeBody](env)
		if err != nil {
			return
		}
		m.mu.Lock()
		p := m.peers[peer]
		m.mu.Unlock()
		if p != nil && p.session == b.Session {
			go p.close(&ByeError{Reason: b.Reason}, false, "")
		}
	}
}

func (m *Mesh) answer(p *Peer, remote string) {
	if err := p.setup(); err != nil {
		p.close(err, false, "")
		return
	}
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: remote}); err != nil {
		p.close(err, true, "bad offer")
		return
	}
	ans, err := p.pc.CreateAnswer(nil)
	if err != nil {
		p.close(err, true, "bad offer")
		return
	}
	sdp, err := p.gather(ans)
	if err != nil {
		p.close(err, false, "")
		return
	}
	if err := m.sig.Send(p.id, MsgAnswer, sdpBody{Session: p.session, SDP: sdp}); err != nil {
		p.close(fmt.Errorf("room: sending the answer: %w", err), false, "")
	}
}

// ByeError is why a peer went down when the other side closed it.
type ByeError struct{ Reason string }

func (e *ByeError) Error() string {
	if e.Reason == "" {
		return "room: closed by peer"
	}
	return "room: closed by peer: " + e.Reason
}

// forget drops p from the mesh and keeps the offerer's backoff.
func (m *Mesh) forget(p *Peer, wasUp bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peers[p.id] == p {
		delete(m.peers, p.id)
		// The next Connect may ask again at once.
		delete(m.wantAt, p.id)
	}
	if !p.offerer {
		return
	}
	if wasUp {
		if r := m.retry[p.id]; r != nil && r.timer != nil {
			r.timer.Stop()
		}
		delete(m.retry, p.id)
		return
	}
	r := m.retry[p.id]
	if r == nil {
		r = &retryState{}
		m.retry[p.id] = r
	}
	r.backoff = min(max(r.backoff*2, backoffMin), backoffMax)
	r.next = time.Now().Add(r.backoff)
}

func (m *Mesh) peerUp(p *Peer) {
	m.mu.Lock()
	if r := m.retry[p.id]; r != nil && r.timer != nil {
		r.timer.Stop()
	}
	delete(m.retry, p.id)
	fn := m.onPeer
	m.mu.Unlock()
	if fn != nil {
		m.emit(func() { fn(p) })
	}
}

func (m *Mesh) peerDown(id string, err error) {
	m.mu.Lock()
	fn := m.onDown
	m.mu.Unlock()
	if fn != nil {
		m.emit(func() { fn(id, err) })
	}
}

// emit queues a callback; callbacks run one at a time, in order, on the
// mesh's event goroutine and never under a lock or inside pion.
func (m *Mesh) emit(fn func()) {
	m.evMu.Lock()
	m.events = append(m.events, fn)
	m.evMu.Unlock()
	select {
	case m.evWake <- struct{}{}:
	default:
	}
}

func (m *Mesh) eventLoop() {
	defer close(m.evDone)
	for {
		m.evMu.Lock()
		if len(m.events) > 0 {
			fn := m.events[0]
			m.events = m.events[1:]
			m.evMu.Unlock()
			fn()
			continue
		}
		m.evMu.Unlock()
		select {
		case <-m.evWake:
		case <-m.evClose:
			return
		}
	}
}

// Close closes every connection (telling each peer) and stops handling the
// signaler's rtc.* envelopes. It waits for pion to finish closing, and for
// queued OnPeer/OnPeerDown callbacks to run; don't call it from one.
func (m *Mesh) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	var all []*Peer
	for _, p := range m.peers {
		all = append(all, p)
	}
	for _, r := range m.retry {
		if r.timer != nil {
			r.timer.Stop()
		}
	}
	m.mu.Unlock()
	m.sig.core().setRTC(nil)
	for _, p := range all {
		p.close(ErrClosed, true, "closing")
	}
	m.pcs.Wait()
	m.emit(func() { close(m.evClose) })
	<-m.evDone
}

// --- the auth handshake ---------------------------------------------------

const authContext = "go-room/auth/1"

type authMsg struct {
	V         int    `json:"v"`
	DeviceID  string `json:"deviceId"`
	DevicePub string `json:"devicePub"` // hex
	Sig       string `json:"sig"`       // hex
}

type authResult struct {
	V   int    `json:"v"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// authPayload is what each side signs: the context, its role, both DTLS
// certificate fingerprints as the transport saw them (offerer's first), the
// room's topic hash and the signer's own id.
func authPayload(offerer bool, fpOfferer, fpAnswerer []byte, topicHash [32]byte, self string) []byte {
	b := make([]byte, 0, len(authContext)+2+32*3+1+len(self))
	b = append(b, authContext...)
	b = append(b, 0)
	if offerer {
		b = append(b, 'O')
	} else {
		b = append(b, 'A')
	}
	b = append(b, fpOfferer...)
	b = append(b, fpAnswerer...)
	b = append(b, topicHash[:]...)
	b = append(b, byte(len(self)))
	b = append(b, self...)
	return b
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only our own fixed structs come here
	}
	return b
}

// handshake runs on the sync channel once it opens: both sides send auth,
// check the other's, ask Accept, and exchange the result. The peer is up
// only when both sides accepted.
func (p *Peer) handshake(ctx context.Context) error {
	m := p.m
	var fpO, fpA []byte
	if p.offerer {
		fpO, fpA = p.fpLocal, p.fpRemote
	} else {
		fpO, fpA = p.fpRemote, p.fpLocal
	}
	sig := m.cfg.Identity.Sign(authPayload(p.offerer, fpO, fpA, m.topicHash, m.cfg.Self))
	mine := authMsg{V: 1, DeviceID: m.cfg.Self, DevicePub: hexs(m.cfg.Identity.Pub), Sig: hexs(sig)}
	if err := p.msgs.Send(ctx, marshal(mine)); err != nil {
		return err
	}
	raw, err := p.msgs.Recv(ctx)
	if err != nil {
		return fmt.Errorf("room: waiting for auth: %w", err)
	}
	var theirs authMsg
	if json.Unmarshal(raw, &theirs) != nil || theirs.V != 1 {
		return errors.New("room: bad auth message")
	}
	if theirs.DeviceID != p.id {
		return fmt.Errorf("room: auth names %q, signaling said %q", theirs.DeviceID, p.id)
	}
	pub, err1 := unhex(theirs.DevicePub)
	sigB, err2 := unhex(theirs.Sig)
	if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("room: bad auth message")
	}
	if !ed25519.Verify(pub, authPayload(!p.offerer, fpO, fpA, m.topicHash, p.id), sigB) {
		return errors.New("room: auth signature doesn't verify")
	}
	p.pub = ed25519.PublicKey(pub)
	verdict := m.cfg.Accept(p.id, p.pub)
	res := authResult{V: 1, OK: verdict == nil}
	if verdict != nil {
		res.Err = "refused"
	}
	if err := p.msgs.Send(ctx, marshal(res)); err != nil {
		return err
	}
	if verdict != nil {
		return fmt.Errorf("%w %s: %w", errRefusedHere, p.id, verdict)
	}
	raw, err = p.msgs.Recv(ctx)
	if err != nil {
		return fmt.Errorf("room: waiting for the auth result: %w", err)
	}
	var theirRes authResult
	if json.Unmarshal(raw, &theirRes) != nil || theirRes.V != 1 {
		return errors.New("room: bad auth result")
	}
	if !theirRes.OK {
		return ErrRefused
	}
	return nil
}

// ErrRefused means the other side's Accept turned this side down.
var ErrRefused = errors.New("room: refused by peer")

// errRefusedHere wraps this side's own Accept refusal.
var errRefusedHere = errors.New("room: refused")

// LoopbackOnly keeps pion on 127.0.0.1: UDP4 only, loopback candidates
// included, every other address filtered out (no LAN host candidates, so a
// fresh test binary raises no Windows Firewall prompt). Pair it with an ICE
// list that returns nil, so no STUN gathering socket is opened.
func LoopbackOnly() func(*webrtc.SettingEngine) {
	return func(se *webrtc.SettingEngine) {
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
		se.SetIncludeLoopbackCandidate(true)
		se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
		se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	}
}
