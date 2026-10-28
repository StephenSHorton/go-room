package room

import (
	"sync"
)

// MemHub is an in-process stand-in for the public brokers, for tests: every
// Signaler opened on it publishes sealed bytes to the hub, and the hub hands
// them to every Signaler subscribed to the same topic, each in order on its
// own goroutine. Sealing, filtering, de-duplication and the age check are
// the same code OpenSignal uses; only the transport differs.
type MemHub struct {
	mu   sync.Mutex
	subs map[string][]*memSignal // by topic

	// Tap, when set, sees every payload published (topic, sealed bytes):
	// tests use it to check what a broker would see.
	Tap func(topic string, payload []byte)
}

// NewMemHub returns an empty hub.
func NewMemHub() *MemHub { return &MemHub{subs: map[string][]*memSignal{}} }

// Open joins the room for s as member self. OnConnect fires once, at once.
func (h *MemHub) Open(s Secret, self string, o SignalOptions) Signaler {
	c, err := newCore(s, self, o)
	if err != nil {
		// The broker path returns this error; a test hub panics so the test
		// sees it at the call.
		panic(err)
	}
	m := &memSignal{c: c, hub: h, wake: make(chan struct{}, 1), done: make(chan struct{})}
	h.mu.Lock()
	h.subs[c.topic] = append(h.subs[c.topic], m)
	h.mu.Unlock()
	go m.loop()
	if o.OnConnect != nil {
		go o.OnConnect()
	}
	return m
}

// Publish delivers a raw payload on topic as a broker would, for tests that
// replay or forge traffic.
func (h *MemHub) Publish(topic string, payload []byte) {
	h.mu.Lock()
	tap := h.Tap
	subs := append([]*memSignal(nil), h.subs[topic]...)
	h.mu.Unlock()
	if tap != nil {
		tap(topic, payload)
	}
	for _, s := range subs {
		s.enqueue(payload)
	}
}

func (h *MemHub) remove(m *memSignal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.subs[m.c.topic]
	for i, s := range list {
		if s == m {
			h.subs[m.c.topic] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(h.subs[m.c.topic]) == 0 {
		delete(h.subs, m.c.topic)
	}
}

type memSignal struct {
	c   *sigCore
	hub *MemHub

	mu    sync.Mutex
	queue [][]byte
	wake  chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (m *memSignal) core() *sigCore { return m.c }
func (m *memSignal) Self() string   { return m.c.self }
func (m *memSignal) Topic() string  { return m.c.topic }

func (m *memSignal) Connected() int {
	if m.c.isClosed() {
		return 0
	}
	return 1
}

func (m *memSignal) Send(to, typ string, body any) error {
	if m.c.isClosed() {
		return ErrClosed
	}
	sealed, err := m.c.seal(to, typ, body)
	if err != nil {
		return err
	}
	m.hub.Publish(m.c.topic, sealed)
	return nil
}

func (m *memSignal) Close() {
	m.once.Do(func() {
		m.c.close()
		m.hub.remove(m)
		close(m.done)
	})
}

func (m *memSignal) enqueue(p []byte) {
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
func (m *memSignal) loop() {
	for {
		select {
		case <-m.done:
			return
		case <-m.wake:
		}
		for {
			m.mu.Lock()
			if len(m.queue) == 0 {
				m.mu.Unlock()
				break
			}
			p := m.queue[0]
			m.queue = m.queue[1:]
			m.mu.Unlock()
			m.c.receive(p)
		}
	}
}
