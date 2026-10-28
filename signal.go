package room

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

// DefaultMaxAge drops anything older (or further ahead) than this: a carrier
// replaying a backlog after a reconnect, or a clock far off.
const DefaultMaxAge = 2 * time.Minute

// RTCPrefix starts the envelope types Mesh owns ("rtc.want", "rtc.offer",
// "rtc.answer", "rtc.bye"). They never reach SignalOptions.OnMsg.
const RTCPrefix = "rtc."

// seenCap is how many envelope ids are remembered before old ones are pruned.
const seenCap = 2048

// Envelope is one signaling message. To == "" is for everyone. The JSON
// shape is Toru's, so Toru can move onto go-room without a wire change.
type Envelope struct {
	V    int             `json:"v"`
	ID   string          `json:"id"`
	From string          `json:"from"`
	To   string          `json:"to,omitempty"`
	Type string          `json:"type"`
	At   int64           `json:"at"` // unix ms
	Body json.RawMessage `json:"body,omitempty"`
}

// Decode unmarshals an envelope's body.
func Decode[T any](env Envelope) (T, error) {
	var v T
	if err := json.Unmarshal(env.Body, &v); err != nil {
		return v, fmt.Errorf("bad %s message: %w", env.Type, err)
	}
	return v, nil
}

// Signaler is a live connection to one room over one or more carriers:
// Open, MemHub.Open (tests) or mqtt.OpenSignal (public brokers). The
// unexported method keeps implementations inside go-room, because Mesh
// relies on how they seal, filter and route.
type Signaler interface {
	// Send seals one envelope to member to ("" = everyone) and publishes it
	// on every carrier.
	Send(to, typ string, body any) error
	// Connected reports how many carriers are up right now.
	Connected() int
	// Self is this member's id.
	Self() string
	// Topic is the room's topic (from its Secret).
	Topic() string
	// Close leaves the room.
	Close()

	core() *sigCore
}

// SignalOptions tune a Signaler. The zero value is Toru's behaviour.
type SignalOptions struct {
	// MaxAge drops envelopes older or further ahead than this (default
	// DefaultMaxAge).
	MaxAge time.Duration
	// OnMsg gets every envelope from another member, addressed to everyone
	// or to self, that isn't one of Mesh's own rtc.* types. It runs on the
	// signaler's receive goroutine; don't block it for long.
	OnMsg func(Envelope)
	// OnConnect fires whenever a carrier (re)connects, so callers can
	// announce themselves.
	OnConnect func()
	// OnHeard, when set, gets the sender and source address of every
	// authentic envelope that arrived with one (the LAN carrier), duplicates
	// included: how an app learns where a member is on the local network.
	// It runs on the carrier's receive goroutine.
	OnHeard func(from string, addr netip.AddrPort)
}

// A Carrier moves sealed payloads for topics. It never holds a key: Open
// seals, opens, filters and de-duplicates, so every carrier gets the same
// checks. A Carrier may serve many rooms at once.
type Carrier interface {
	// Join starts carrying topic. deliver gets every payload that arrives
	// for it, with the address it came from when the carrier knows one (the
	// zero AddrPort otherwise); up runs each time the leg (re)connects.
	// Neither may block for long.
	Join(topic string, deliver func(payload []byte, from netip.AddrPort), up func()) (Leg, error)
}

// A Leg is one topic on one Carrier.
type Leg interface {
	// Publish sends one sealed payload. to is the member it is for ("" =
	// everyone); a carrier may ignore it (a hub or a broker sends to every
	// subscriber), and the LAN carrier unicasts when it knows the address.
	Publish(to string, payload []byte) error
	// Seen tells the leg that a payload it delivered from addr opened as an
	// authentic envelope from member.
	Seen(member string, from netip.AddrPort)
	// Up reports whether the leg can publish right now.
	Up() bool
	// Close stops carrying the topic.
	Close()
}

// sigCore is the part of every Signaler that doesn't care how bytes move:
// sealing, opening, filtering, de-duplication and the age check.
type sigCore struct {
	self   string
	key    [32]byte
	topic  string
	maxAge time.Duration
	onMsg  func(Envelope)
	heard  func(string, netip.AddrPort)
	now    func() time.Time

	mu     sync.Mutex
	seen   map[string]time.Time
	rtc    func(Envelope)
	closed bool
}

func newCore(s Secret, self string, o SignalOptions) (*sigCore, error) {
	if s.Topic == "" {
		return nil, errors.New("room: secret has no topic")
	}
	if self == "" || strings.ContainsAny(self, "/#+") {
		return nil, errors.New("room: bad member id")
	}
	maxAge := o.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	return &sigCore{self: self, key: s.Key, topic: s.Topic, maxAge: maxAge, onMsg: o.OnMsg, heard: o.OnHeard, now: time.Now, seen: map[string]time.Time{}}, nil
}

// seal builds and seals one envelope.
func (c *sigCore) seal(to, typ string, body any) ([]byte, error) {
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	env := Envelope{V: 1, ID: randHex(8), From: c.self, To: to, Type: typ, At: c.now().UnixMilli(), Body: raw}
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], plain, &nonce, &c.key), nil
}

// open checks one sealed payload and returns its envelope if it is for this
// member: sealed with this room's key, well formed, not from self, addressed
// to everyone or to self, and within maxAge. It doesn't de-duplicate.
func (c *sigCore) open(payload []byte) (Envelope, bool) {
	var env Envelope
	if len(payload) < 24+secretbox.Overhead {
		return env, false
	}
	var nonce [24]byte
	copy(nonce[:], payload[:24])
	plain, ok := secretbox.Open(nil, payload[24:], &nonce, &c.key)
	if !ok {
		return env, false // not ours, or tampered with
	}
	if json.Unmarshal(plain, &env) != nil || env.V != 1 || env.ID == "" || env.From == "" {
		return env, false
	}
	if env.From == c.self || (env.To != "" && env.To != c.self) {
		return env, false
	}
	if age := c.now().Sub(time.UnixMilli(env.At)); age > c.maxAge || age < -c.maxAge {
		return env, false
	}
	return env, true
}

// receive opens, checks, de-duplicates and routes one payload.
func (c *sigCore) receive(payload []byte) { c.receiveFrom(payload, nil, netip.AddrPort{}) }

// receiveFrom is receive for a payload leg delivered from addr: an authentic
// one is reported to the leg (and OnHeard) before de-duplication, so a
// carrier learns every path a member is heard on, not only the fastest.
func (c *sigCore) receiveFrom(payload []byte, leg Leg, from netip.AddrPort) {
	env, ok := c.open(payload)
	if !ok {
		return
	}
	if from.IsValid() {
		if leg != nil {
			leg.Seen(env.From, from)
		}
		if c.heard != nil && !c.isClosed() {
			c.heard(env.From, from)
		}
	}
	now := c.now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if _, dup := c.seen[env.ID]; dup {
		c.mu.Unlock()
		return
	}
	c.seen[env.ID] = now
	if len(c.seen) > seenCap {
		for id, t := range c.seen {
			if now.Sub(t) > 2*c.maxAge {
				delete(c.seen, id)
			}
		}
	}
	rtc := c.rtc
	c.mu.Unlock()
	if strings.HasPrefix(env.Type, RTCPrefix) {
		if rtc != nil {
			rtc(env)
		}
		return
	}
	if c.onMsg != nil {
		c.onMsg(env)
	}
}

func (c *sigCore) setRTC(fn func(Envelope)) {
	c.mu.Lock()
	c.rtc = fn
	c.mu.Unlock()
}

// close marks the core closed; it reports whether it was open.
func (c *sigCore) close() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.closed = true
	c.rtc = nil
	return true
}

func (c *sigCore) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// --- Open: one Signaler over many carriers --------------------------------

type signal struct {
	c         *sigCore
	legs      []Leg
	onConnect func()
	once      sync.Once
}

// Open joins the room for s as member self over every carrier given. Each
// envelope is sealed once and published on all of them, and the first copy
// to arrive wins (the rest are dropped by id), so one carrier being down or
// slow changes nothing. It returns at once; carriers connect (and
// reconnect) in the background, and OnConnect fires on each.
func Open(s Secret, self string, o SignalOptions, carriers ...Carrier) (Signaler, error) {
	c, err := newCore(s, self, o)
	if err != nil {
		return nil, err
	}
	if len(carriers) == 0 {
		return nil, errors.New("room: no carriers")
	}
	r := &signal{c: c, onConnect: o.OnConnect}
	up := func() {
		if r.onConnect != nil && !c.isClosed() {
			go r.onConnect()
		}
	}
	for _, car := range carriers {
		if car == nil {
			continue
		}
		// A carrier may deliver before Join returns; until then the leg
		// isn't told what it carried (Seen), which costs nothing.
		var leg atomic.Pointer[Leg]
		l, err := car.Join(c.topic, func(p []byte, from netip.AddrPort) {
			var lg Leg
			if lp := leg.Load(); lp != nil {
				lg = *lp
			}
			c.receiveFrom(p, lg, from)
		}, up)
		if err != nil {
			r.closeLegs()
			return nil, err
		}
		leg.Store(&l)
		r.legs = append(r.legs, l)
	}
	if len(r.legs) == 0 {
		return nil, errors.New("room: no carriers")
	}
	return r, nil
}

func (r *signal) core() *sigCore { return r.c }
func (r *signal) Self() string   { return r.c.self }
func (r *signal) Topic() string  { return r.c.topic }

func (r *signal) Connected() int {
	if r.c.isClosed() {
		return 0
	}
	n := 0
	for _, l := range r.legs {
		if l.Up() {
			n++
		}
	}
	return n
}

func (r *signal) Send(to, typ string, body any) error {
	if r.c.isClosed() {
		return ErrClosed
	}
	sealed, err := r.c.seal(to, typ, body)
	if err != nil {
		return err
	}
	sent := 0
	var last error
	for _, l := range r.legs {
		if !l.Up() {
			continue
		}
		if err := l.Publish(to, sealed); err != nil {
			last = err
			continue
		}
		sent++
	}
	if sent == 0 {
		if last != nil {
			return last
		}
		return ErrNotConnected
	}
	return nil
}

// Close leaves the room on every carrier.
func (r *signal) Close() {
	r.once.Do(func() {
		r.c.close()
		r.closeLegs()
	})
}

func (r *signal) closeLegs() {
	var wg sync.WaitGroup
	for _, l := range r.legs {
		wg.Add(1)
		go func(l Leg) {
			defer wg.Done()
			l.Close()
		}(l)
	}
	wg.Wait()
}

// ErrNotConnected is Send's error while no carrier is up.
var ErrNotConnected = errors.New("not connected to the room yet")

// ErrClosed is returned by anything used after Close.
var ErrClosed = errors.New("room: closed")

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
