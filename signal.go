package room

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/crypto/nacl/secretbox"
)

// DefaultBrokers are independent public MQTT brokers; each entry is one
// client tried over raw TLS first and WebSockets-over-TLS second (some
// networks block 8883). Messages go out through all of them and are
// de-duplicated on arrival, so one broker being down or slow changes nothing.
var DefaultBrokers = [][]string{
	{"tls://broker.emqx.io:8883", "wss://broker.emqx.io:8084/mqtt"},
	{"tls://broker.hivemq.com:8883", "wss://broker.hivemq.com:8884/mqtt"},
}

// DefaultMaxAge drops anything older (or further ahead) than this: a broker
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

// Signaler is a live connection to one room: OpenSignal (public brokers) or
// MemHub.Open (tests). The unexported method keeps implementations inside
// go-room, because Mesh relies on how they seal, filter and route.
type Signaler interface {
	// Send seals and publishes one envelope to member to ("" = everyone).
	Send(to, typ string, body any) error
	// Connected reports how many brokers are connected right now.
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
	// Brokers are the broker sets (default DefaultBrokers). Each inner list
	// is one client's broker URLs, tried in order.
	Brokers [][]string
	// ClientPrefix starts each MQTT client id (default "go-room-"). The rest
	// is random, so the member id never reaches the broker.
	ClientPrefix string
	// MaxAge drops envelopes older or further ahead than this (default
	// DefaultMaxAge).
	MaxAge time.Duration
	// OnMsg gets every envelope from another member, addressed to everyone
	// or to self, that isn't one of Mesh's own rtc.* types. It runs on the
	// signaler's receive goroutine; don't block it for long.
	OnMsg func(Envelope)
	// OnConnect fires whenever a broker (re)connects, so callers can announce
	// themselves.
	OnConnect func()
}

// sigCore is the part of every Signaler that doesn't care how bytes move:
// sealing, opening, filtering, de-duplication and the age check.
type sigCore struct {
	self   string
	key    [32]byte
	topic  string
	maxAge time.Duration
	onMsg  func(Envelope)
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
	return &sigCore{self: self, key: s.Key, topic: s.Topic, maxAge: maxAge, onMsg: o.OnMsg, now: time.Now, seen: map[string]time.Time{}}, nil
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
func (c *sigCore) receive(payload []byte) {
	env, ok := c.open(payload)
	if !ok {
		return
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

// --- MQTT ---------------------------------------------------------------

type mqttSignal struct {
	c         *sigCore
	clients   []mqtt.Client
	onConnect func()
}

// OpenSignal joins the room for s as member self over the public brokers. It
// returns at once; brokers connect (and reconnect) in the background.
func OpenSignal(s Secret, self string, o SignalOptions) (Signaler, error) {
	c, err := newCore(s, self, o)
	if err != nil {
		return nil, err
	}
	brokers := o.Brokers
	if len(brokers) == 0 {
		brokers = DefaultBrokers
	}
	prefix := o.ClientPrefix
	if prefix == "" {
		prefix = "go-room-"
	}
	r := &mqttSignal{c: c, onConnect: o.OnConnect}
	for _, set := range brokers {
		if len(set) == 0 {
			continue
		}
		opts := mqtt.NewClientOptions().
			SetClientID(prefix + randHex(8)).
			SetCleanSession(true).
			SetAutoReconnect(true).
			SetConnectRetry(true).
			SetConnectRetryInterval(3 * time.Second).
			SetMaxReconnectInterval(15 * time.Second).
			SetConnectTimeout(8 * time.Second).
			SetKeepAlive(30 * time.Second).
			SetOrderMatters(false)
		for _, b := range set {
			opts.AddBroker(b)
		}
		opts.SetOnConnectHandler(func(cl mqtt.Client) {
			// Clean sessions forget subscriptions, so (re)subscribe on every connect.
			cl.Subscribe(c.topic, 1, func(_ mqtt.Client, m mqtt.Message) { c.receive(m.Payload()) })
			if r.onConnect != nil && !c.isClosed() {
				go r.onConnect()
			}
		})
		cl := mqtt.NewClient(opts)
		cl.Connect() // with ConnectRetry this keeps trying in the background
		r.clients = append(r.clients, cl)
	}
	if len(r.clients) == 0 {
		return nil, errors.New("room: no brokers")
	}
	return r, nil
}

func (r *mqttSignal) core() *sigCore { return r.c }
func (r *mqttSignal) Self() string   { return r.c.self }
func (r *mqttSignal) Topic() string  { return r.c.topic }

func (r *mqttSignal) Connected() int {
	n := 0
	for _, cl := range r.clients {
		if cl.IsConnectionOpen() {
			n++
		}
	}
	return n
}

func (r *mqttSignal) Send(to, typ string, body any) error {
	if r.c.isClosed() {
		return ErrClosed
	}
	sealed, err := r.c.seal(to, typ, body)
	if err != nil {
		return err
	}
	sent := 0
	for _, cl := range r.clients {
		if !cl.IsConnectionOpen() {
			continue
		}
		cl.Publish(r.c.topic, 1, false, sealed)
		sent++
	}
	if sent == 0 {
		return ErrNotConnected
	}
	return nil
}

// Close leaves the room. Pending messages get a moment to flush.
func (r *mqttSignal) Close() {
	if !r.c.close() {
		return
	}
	var wg sync.WaitGroup
	for _, cl := range r.clients {
		wg.Add(1)
		go func(cl mqtt.Client) {
			defer wg.Done()
			cl.Disconnect(250)
		}(cl)
	}
	wg.Wait()
}

// ErrNotConnected is Send's error while no broker is connected.
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
