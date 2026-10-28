package room

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v4"
)

// SyncLabel is the label of every peer's message channel (pre-negotiated,
// stream id 0). OpenStream refuses it.
const SyncLabel = "sync"

// Peer states.
const (
	statePending = iota
	stateUp
	stateClosed
)

// Peer is one authenticated connection to another member.
type Peer struct {
	m        *Mesh
	id       string
	session  string
	offerer  bool
	pc       *webrtc.PeerConnection
	up       chan struct{}
	done     chan struct{}
	timer    *time.Timer
	outSem   chan struct{}
	pub      ed25519.PublicKey
	fpLocal  []byte
	fpRemote []byte
	msgs     *Channel
	offerAt  int64  // answerer: the offer envelope's At (the offerer's clock)
	token    string // sent in this side's auth; a bye to an up peer must carry it
	theirTok string // the peer's auth token, put in this side's byes
	shown    bool   // under m.mu: OnPeer was queued for it

	mu       sync.Mutex
	state    int
	err      error
	upTime   time.Time
	answered bool
	onStream func(string, *Stream)
	pending  []*Stream
	streams  map[*Stream]struct{}
	inCount  int
	once     sync.Once
}

// ID is the peer's member id.
func (p *Peer) ID() string { return p.id }

// Session is this connection's id (fresh for every attempt).
func (p *Peer) Session() string { return p.session }

// Pub is the ed25519 key the peer proved it holds.
func (p *Peer) Pub() ed25519.PublicKey { return p.pub }

// Fingerprints are the SHA-256 fingerprints of this side's and the peer's
// DTLS certificates, as the connected transport saw them (not the SDP), in
// lower-case colon hex. Both sides see the same pair, swapped; a pairing
// SAS over both catches a man in the middle.
func (p *Peer) Fingerprints() (local, remote string) {
	return fpString(p.fpLocal), fpString(p.fpRemote)
}

// Messages is the peer's one reliable, ordered message channel.
func (p *Peer) Messages() *Channel { return p.msgs }

// Done is closed once the peer is down.
func (p *Peer) Done() <-chan struct{} { return p.done }

// Err is why the peer went down (nil while up).
func (p *Peer) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Path is "relay" when the selected ICE pair goes through TURN, "direct"
// otherwise ("" before a pair is selected).
func (p *Peer) Path() string {
	if p.pc == nil || p.pc.SCTP() == nil || p.pc.SCTP().Transport() == nil {
		return ""
	}
	pair, err := p.pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return ""
	}
	if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
		return "relay"
	}
	return "direct"
}

// healthy reports whether ICE still hears the peer (consent checks are
// authenticated by ICE, so signaling can't fake this).
func (p *Peer) healthy() bool {
	if p.pc == nil {
		return false
	}
	switch p.pc.ICEConnectionState() {
	case webrtc.ICEConnectionStateConnected, webrtc.ICEConnectionStateCompleted:
		return true
	}
	return false
}

// RTT is the latest ICE round-trip time on the nominated pair (0 if none
// measured yet).
func (p *Peer) RTT() time.Duration {
	if p.pc == nil {
		return 0
	}
	for _, s := range p.pc.GetStats() {
		if cp, ok := s.(webrtc.ICECandidatePairStats); ok && cp.Nominated && cp.CurrentRoundTripTime > 0 {
			return time.Duration(cp.CurrentRoundTripTime * float64(time.Second))
		}
	}
	return 0
}

// OnStream sets the handler for streams the peer opens. Streams that arrived
// before it was set are handed to it at once. Without a handler, streams
// wait (up to MaxStreams) until one is set.
func (p *Peer) OnStream(fn func(label string, s *Stream)) {
	p.mu.Lock()
	p.onStream = fn
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, s := range pending {
		go fn(s.label, s)
	}
}

// OpenStream opens a new byte stream to the peer. It waits for one of the
// MaxStreams slots, then for the channel to open.
func (p *Peer) OpenStream(ctx context.Context, label string) (*Stream, error) {
	if label == "" || label == SyncLabel {
		return nil, fmt.Errorf("room: stream label %q is reserved", label)
	}
	if !p.isUp() {
		return nil, ErrClosed
	}
	select {
	case p.outSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, p.closedErr()
	}
	release := sync.OnceFunc(func() { <-p.outSem })
	ordered := true
	dc, err := p.pc.CreateDataChannel(label, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		release()
		return nil, err
	}
	opened := make(chan *Stream, 1)
	failed := make(chan error, 1)
	dc.OnOpen(func() {
		raw, err := dc.Detach()
		if err != nil {
			failed <- err
			return
		}
		opened <- newStream(label, raw.(*datachannel.DataChannel), release)
	})
	select {
	case s := <-opened:
		if !p.track(s) {
			s.abort(p.closedErr())
			return nil, p.closedErr()
		}
		return s, nil
	case err := <-failed:
		_ = dc.Close()
		release()
		return nil, err
	case <-ctx.Done():
		_ = dc.Close()
		release()
		return nil, ctx.Err()
	case <-p.done:
		release()
		return nil, p.closedErr()
	}
}

// Close closes the connection and every stream on it, and tells the peer
// why with an rtc.bye.
func (p *Peer) Close(reason string) {
	p.close(&LocalCloseError{Reason: reason}, true, reason)
}

// LocalCloseError is why a peer went down when this side closed it.
type LocalCloseError struct{ Reason string }

func (e *LocalCloseError) Error() string { return "room: closed: " + e.Reason }

func (p *Peer) isUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state == stateUp
}

func (p *Peer) upAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.upTime
}

func (p *Peer) closedErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	return ErrClosed
}

// track records a stream, so closing the peer closes it.
func (p *Peer) track(s *Stream) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == stateClosed {
		return false
	}
	p.streams[s] = struct{}{}
	inner := s.release
	s.release = func() {
		p.mu.Lock()
		delete(p.streams, s)
		p.mu.Unlock()
		if inner != nil {
			inner()
		}
	}
	return true
}

// setup makes the PeerConnection and its pre-negotiated sync channel.
func (p *Peer) setup() error {
	m := p.m
	servers := DefaultSTUN
	if m.cfg.ICE != nil {
		servers = m.cfg.ICE()
	}
	conf := webrtc.Configuration{ICEServers: WebRTCServers(servers)}
	if m.cfg.RelayOnly {
		conf.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := m.api.NewPeerConnection(conf)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.state == stateClosed {
		p.mu.Unlock()
		_ = pc.Close()
		return p.closedErr()
	}
	p.pc = pc
	p.mu.Unlock()

	negotiated, ordered := true, true
	id := uint16(0)
	dc, err := pc.CreateDataChannel(SyncLabel, &webrtc.DataChannelInit{Negotiated: &negotiated, ID: &id, Ordered: &ordered})
	if err != nil {
		return err
	}
	dc.OnOpen(func() { go p.syncOpen(dc) })
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Negotiated() || dc.Label() == SyncLabel {
			return
		}
		label := dc.Label()
		dc.OnOpen(func() {
			raw, err := dc.Detach()
			if err != nil {
				_ = dc.Close()
				return
			}
			p.incoming(label, raw.(*datachannel.DataChannel))
		})
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		switch s {
		case webrtc.PeerConnectionStateFailed:
			p.lost(errors.New("room: connection failed"))
		case webrtc.PeerConnectionStateClosed:
			p.lost(errors.New("room: connection closed"))
		}
	})
	return nil
}

// gather sets the local description and waits for ICE gathering (4 s cap),
// returning the SDP with every candidate found.
func (p *Peer) gather(desc webrtc.SessionDescription) (string, error) {
	gathered := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	select {
	case <-gathered:
	case <-time.After(gatherCap):
	case <-p.done:
		return "", p.closedErr()
	}
	return p.pc.LocalDescription().SDP, nil
}

func (p *Peer) setAnswer(sdp string) {
	p.mu.Lock()
	if p.answered || p.state != statePending || p.pc == nil {
		p.mu.Unlock()
		return
	}
	p.answered = true
	p.mu.Unlock()
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}); err != nil {
		// Maybe a forged answer that raced the real one: wait for another.
		p.m.cfg.Logf("room: bad answer from %s: %v", p.id, err)
		p.mu.Lock()
		p.answered = false
		p.mu.Unlock()
	}
}

// syncOpen runs once DTLS and SCTP are up: read both fingerprints off the
// transport, detach the sync channel and run the handshake.
func (p *Peer) syncOpen(dc *webrtc.DataChannel) {
	m := p.m
	dtls := p.pc.SCTP().Transport()
	lp, err := dtls.GetLocalParameters()
	if err != nil {
		p.close(err, true, "dtls")
		return
	}
	for _, f := range lp.Fingerprints {
		if strings.EqualFold(f.Algorithm, "sha-256") {
			p.fpLocal, _ = parseFP(f.Value)
		}
	}
	der := dtls.GetRemoteCertificate()
	if len(p.fpLocal) != 32 || len(der) == 0 {
		p.close(errors.New("room: no DTLS fingerprints"), true, "dtls")
		return
	}
	sum := sha256.Sum256(der)
	p.fpRemote = sum[:]

	raw, err := dc.Detach()
	if err != nil {
		p.close(err, true, "detach")
		return
	}
	ch := newChannel(raw.(*datachannel.DataChannel), m.cfg.MaxMessage, p.lost)
	p.mu.Lock()
	if p.state == stateClosed {
		p.mu.Unlock()
		ch.close(p.closedErr())
		return
	}
	p.msgs = ch
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.AuthTimeout)
	go func() {
		select {
		case <-p.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	err = p.handshake(ctx)
	cancel()
	if err != nil {
		m.cfg.Logf("room: handshake with %s: %v", p.id, err)
		switch {
		case errors.Is(err, ErrRefused):
			p.close(err, false, "") // the other side already said so
		case errors.Is(err, errRefusedHere):
			p.close(err, true, "refused")
		default:
			p.close(err, true, "auth failed")
		}
		return
	}

	p.mu.Lock()
	if p.state != statePending {
		p.mu.Unlock()
		return
	}
	p.state = stateUp
	p.upTime = time.Now()
	p.mu.Unlock()
	p.timer.Stop()
	close(p.up)
	m.peerUp(p)
}

// incoming takes a stream the peer opened.
func (p *Peer) incoming(label string, dc *datachannel.DataChannel) {
	p.mu.Lock()
	// Twice the opener's cap: the opener frees its slot on its own Close,
	// this side only when the handler closes, so for a moment both a
	// finishing stream and its successor are here.
	if p.state == stateClosed || p.inCount >= 2*p.m.cfg.MaxStreams || label == "" || label == SyncLabel {
		p.mu.Unlock()
		_ = dc.Close()
		return
	}
	p.inCount++
	p.mu.Unlock()
	s := newStream(label, dc, func() {
		p.mu.Lock()
		p.inCount--
		p.mu.Unlock()
	})
	if !p.track(s) {
		s.abort(p.closedErr())
		return
	}
	p.mu.Lock()
	fn := p.onStream
	if fn == nil {
		p.pending = append(p.pending, s)
	}
	p.mu.Unlock()
	if fn != nil {
		go fn(label, s)
	}
}

// close tears the connection down once: forget it in the mesh, close every
// channel, optionally tell the peer, close pion, and report the peer down
// if it was up.
func (p *Peer) close(err error, bye bool, reason string) {
	p.once.Do(func() {
		p.mu.Lock()
		wasUp := p.state == stateUp
		p.state = stateClosed
		p.err = err
		pc, msgs := p.pc, p.msgs
		var streams []*Stream
		for s := range p.streams {
			streams = append(streams, s)
		}
		p.pending = nil
		p.mu.Unlock()
		close(p.done)
		if p.timer != nil {
			p.timer.Stop()
		}
		if bye {
			// The token is the peer's own, from its auth (inside DTLS):
			// only this side can prove the bye is real. It goes before the
			// teardown so it usually beats the channel's end to the peer.
			_ = p.m.sig.Send(p.id, MsgBye, byeBody{Session: p.session, Token: p.theirTok, Reason: reason})
		}
		shown := p.m.forget(p, wasUp, err)
		if msgs != nil {
			msgs.close(err)
		}
		for _, s := range streams {
			s.abort(err)
		}
		go func() {
			defer p.m.pcs.Done()
			if pc != nil {
				_ = pc.Close()
			}
		}()
		if shown {
			p.m.peerDown(p.id, err)
		}
	})
}

// byeGrace is how long a connection that ended on its own waits for the
// other side's bye, which travels over signaling and can arrive after the
// channel's end: with it, Down reports the peer's reason, not a bare close.
const byeGrace = time.Second

// lost closes p after byeGrace, unless a bye (or anything else) closed it
// first.
func (p *Peer) lost(err error) {
	go func() {
		t := time.NewTimer(byeGrace)
		defer t.Stop()
		select {
		case <-p.done:
		case <-t.C:
		}
		p.close(err, false, "")
	}()
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) ([]byte, error) { return hex.DecodeString(s) }

// parseFP turns "ab:cd:..." into bytes.
func parseFP(s string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(s, ":", ""))
}

func fpString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := hex.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}
