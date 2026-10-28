// Package mqtt carries go-room signaling over public MQTT brokers, as Toru
// does. It is its own package so an app that never uses brokers never links
// paho: package room has no broker code.
//
// A broker sees a topic (a hash-derived name) and sealed bytes; sealing,
// filtering and de-duplication are room.Open's, the same as every carrier.
package mqtt

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	room "github.com/StephenSHorton/go-room"
	paho "github.com/eclipse/paho.mqtt.golang"
)

// DefaultBrokers are independent public MQTT brokers; each entry is one
// client tried over raw TLS first and WebSockets-over-TLS second (some
// networks block 8883). Messages go out through all of them and are
// de-duplicated on arrival, so one broker being down or slow changes nothing.
var DefaultBrokers = [][]string{
	{"tls://broker.emqx.io:8883", "wss://broker.emqx.io:8084/mqtt"},
	{"tls://broker.hivemq.com:8883", "wss://broker.hivemq.com:8884/mqtt"},
}

// Options pick the brokers.
type Options struct {
	// Brokers are the broker sets (default DefaultBrokers). Each inner list
	// is one client's broker URLs, tried in order.
	Brokers [][]string
	// ClientPrefix starts each MQTT client id (default "go-room-"). The rest
	// is random, so the member id never reaches the broker.
	ClientPrefix string
}

// Carrier is one carrier over every broker set in o: each Join makes one
// client per set, and the leg is up while any of them is connected.
func Carrier(o Options) room.Carrier {
	brokers := o.Brokers
	if len(brokers) == 0 {
		brokers = DefaultBrokers
	}
	prefix := o.ClientPrefix
	if prefix == "" {
		prefix = "go-room-"
	}
	return carrier{brokers: brokers, prefix: prefix}
}

// OpenSignal joins the room for s as member self over the brokers, with one
// carrier per broker set, so Connected counts the sets that are up. It
// returns at once; brokers connect (and reconnect) in the background.
func OpenSignal(s room.Secret, self string, so room.SignalOptions, o Options) (room.Signaler, error) {
	brokers := o.Brokers
	if len(brokers) == 0 {
		brokers = DefaultBrokers
	}
	var cs []room.Carrier
	for _, set := range brokers {
		if len(set) > 0 {
			cs = append(cs, Carrier(Options{Brokers: [][]string{set}, ClientPrefix: o.ClientPrefix}))
		}
	}
	if len(cs) == 0 {
		return nil, errors.New("mqtt: no brokers")
	}
	return room.Open(s, self, so, cs...)
}

type carrier struct {
	brokers [][]string
	prefix  string
}

func (c carrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (room.Leg, error) {
	l := &leg{topic: topic}
	for _, set := range c.brokers {
		if len(set) == 0 {
			continue
		}
		opts := paho.NewClientOptions().
			SetClientID(c.prefix + randHex(8)).
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
		opts.SetOnConnectHandler(func(cl paho.Client) {
			// Clean sessions forget subscriptions, so (re)subscribe on every connect.
			cl.Subscribe(topic, 1, func(_ paho.Client, m paho.Message) { deliver(m.Payload(), netip.AddrPort{}) })
			if up != nil && !l.isClosed() {
				go up()
			}
		})
		cl := paho.NewClient(opts)
		cl.Connect() // with ConnectRetry this keeps trying in the background
		l.clients = append(l.clients, cl)
	}
	if len(l.clients) == 0 {
		return nil, errors.New("mqtt: no brokers")
	}
	return l, nil
}

type leg struct {
	topic   string
	clients []paho.Client

	mu     sync.Mutex
	closed bool
}

func (l *leg) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *leg) Up() bool {
	if l.isClosed() {
		return false
	}
	for _, cl := range l.clients {
		if cl.IsConnectionOpen() {
			return true
		}
	}
	return false
}

func (l *leg) Publish(_ string, payload []byte) error {
	sent := 0
	for _, cl := range l.clients {
		if cl.IsConnectionOpen() {
			cl.Publish(l.topic, 1, false, payload)
			sent++
		}
	}
	if sent == 0 {
		return room.ErrNotConnected
	}
	return nil
}

func (l *leg) Seen(string, netip.AddrPort) {}

// Close disconnects; pending messages get a moment to flush.
func (l *leg) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	var wg sync.WaitGroup
	for _, cl := range l.clients {
		wg.Add(1)
		go func(cl paho.Client) {
			defer wg.Done()
			cl.Disconnect(250)
		}(cl)
	}
	wg.Wait()
}
