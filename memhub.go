package room

import (
	"net/netip"
	"sync"
)

// MemHub is an in-process stand-in for a hub or broker, for tests: every
// Signaler opened on it publishes sealed bytes to the hub, and the hub hands
// them to every other leg subscribed to the same topic, each in order on its
// own goroutine. Sealing, filtering, de-duplication and the age check are
// the same code every carrier gets; only the transport differs.
type MemHub struct {
	mu   sync.Mutex
	subs map[string][]*memLeg // by topic

	// Tap, when set, sees every payload published (topic, sealed bytes):
	// tests use it to check what a carrier would see.
	Tap func(topic string, payload []byte)
}

// NewMemHub returns an empty hub.
func NewMemHub() *MemHub { return &MemHub{subs: map[string][]*memLeg{}} }

// Open joins the room for s as member self, with the hub as its only
// carrier: Open(s, self, o, h.Carrier()). OnConnect fires once, at once.
func (h *MemHub) Open(s Secret, self string, o SignalOptions) Signaler {
	sig, err := Open(s, self, o, h.Carrier())
	if err != nil {
		// Open returns this error; a test hub panics so the test sees it at
		// the call.
		panic(err)
	}
	return sig
}

// Carrier returns the hub as a Carrier, to open beside others.
func (h *MemHub) Carrier() Carrier { return memCarrier{h} }

type memCarrier struct{ h *MemHub }

func (c memCarrier) Join(topic string, deliver func([]byte, netip.AddrPort), up func()) (Leg, error) {
	m := &memLeg{hub: c.h, topic: topic, deliver: deliver, wake: make(chan struct{}, 1), done: make(chan struct{})}
	c.h.mu.Lock()
	c.h.subs[topic] = append(c.h.subs[topic], m)
	c.h.mu.Unlock()
	go m.loop()
	if up != nil {
		go up()
	}
	return m, nil
}

// Publish delivers a raw payload on topic to every leg, as a broker would,
// for tests that replay or forge traffic.
func (h *MemHub) Publish(topic string, payload []byte) { h.publish(nil, topic, payload) }

func (h *MemHub) publish(from *memLeg, topic string, payload []byte) {
	h.mu.Lock()
	tap := h.Tap
	subs := append([]*memLeg(nil), h.subs[topic]...)
	h.mu.Unlock()
	if tap != nil {
		tap(topic, payload)
	}
	for _, s := range subs {
		if s != from {
			s.enqueue(payload)
		}
	}
}

func (h *MemHub) remove(m *memLeg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.subs[m.topic]
	for i, s := range list {
		if s == m {
			h.subs[m.topic] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(h.subs[m.topic]) == 0 {
		delete(h.subs, m.topic)
	}
}

// memLeg is one topic on a MemHub.
type memLeg struct {
	hub     *MemHub
	topic   string
	deliver func([]byte, netip.AddrPort)

	mu     sync.Mutex
	queue  [][]byte
	closed bool
	wake   chan struct{}
	done   chan struct{}
	once   sync.Once
}

func (m *memLeg) Publish(_ string, payload []byte) error {
	if !m.Up() {
		return ErrClosed
	}
	m.hub.publish(m, m.topic, payload)
	return nil
}

func (m *memLeg) Seen(string, netip.AddrPort) {}

func (m *memLeg) Up() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed
}

func (m *memLeg) Close() {
	m.once.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.hub.remove(m)
		close(m.done)
	})
}

func (m *memLeg) enqueue(p []byte) {
	m.mu.Lock()
	m.queue = append(m.queue, append([]byte(nil), p...))
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// loop delivers queued payloads in order, outside every lock, so a receiver
// may Send from its callback.
func (m *memLeg) loop() {
	for {
		select {
		case <-m.done:
			return
		case <-m.wake:
		}
		for {
			m.mu.Lock()
			if len(m.queue) == 0 || m.closed {
				m.mu.Unlock()
				break
			}
			p := m.queue[0]
			m.queue = m.queue[1:]
			m.mu.Unlock()
			m.deliver(p, netip.AddrPort{})
		}
	}
}
