package room

import (
	"net"
	"sync"
	"time"
)

// SplitTCP shares one TCP listener between the hub and TURN over TCP, by
// each connection's first byte: 0x16 (a TLS handshake record) goes to the
// hub, 0x00 or 0x01 (a STUN message) to TURN, anything else is closed. TURN
// ChannelData only ever follows on a connection TURN already has.
//
// Each side is closed on its own; ln closes once both are.
func SplitTCP(ln net.Listener) (hub, turn net.Listener) {
	s := &splitter{ln: ln, gone: make(chan struct{})}
	s.hub = &splitSide{s: s, ch: make(chan net.Conn), done: make(chan struct{}), gone: s.gone}
	s.turn = &splitSide{s: s, ch: make(chan net.Conn), done: make(chan struct{}), gone: s.gone}
	go s.accept()
	return s.hub, s.turn
}

// splitPeekTimeout bounds how long a connection may wait before its first
// byte.
var splitPeekTimeout = 5 * time.Second

type splitter struct {
	ln        net.Listener
	hub, turn *splitSide
	gone      chan struct{} // closed when ln stops accepting
	mu        sync.Mutex
	closed    int // sides closed
}

func (s *splitter) accept() {
	defer close(s.gone)
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go s.route(c)
	}
}

func (s *splitter) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(splitPeekTimeout))
	var b [1]byte
	if _, err := c.Read(b[:]); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := &prefixConn{Conn: c, first: b[0], has: true}
	switch b[0] {
	case 0x16:
		s.hub.deliver(pc)
	case 0x00, 0x01:
		s.turn.deliver(pc)
	default:
		_ = c.Close()
	}
}

func (s *splitter) sideClosed() {
	s.mu.Lock()
	s.closed++
	both := s.closed == 2
	s.mu.Unlock()
	if both {
		_ = s.ln.Close()
	}
}

type splitSide struct {
	s    *splitter
	ch   chan net.Conn
	done chan struct{} // this side closed
	gone chan struct{} // the shared listener stopped
	once sync.Once
}

func (l *splitSide) deliver(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	case <-l.gone:
		_ = c.Close()
	}
}

func (l *splitSide) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.gone:
		return nil, net.ErrClosed
	}
}

func (l *splitSide) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.s.sideClosed()
	})
	return nil
}

func (l *splitSide) Addr() net.Addr { return l.s.ln.Addr() }

// prefixConn gives back the byte SplitTCP read to choose a side.
type prefixConn struct {
	net.Conn
	mu    sync.Mutex
	first byte
	has   bool
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if c.has {
		c.has = false
		c.mu.Unlock()
		p[0] = c.first
		return 1, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}
