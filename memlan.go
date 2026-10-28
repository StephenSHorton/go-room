package room

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// MemLAN is an in-process broadcast domain for tests: each Conn is a
// net.PacketConn with an address of your choosing, a datagram to one Conn's
// address reaches that Conn, and one to Broadcast() reaches every other.
// There are no sockets.
type MemLAN struct {
	mu    sync.Mutex
	conns map[netip.AddrPort]*memPacketConn

	// Drop, when set, is asked about every datagram (from, to); true loses
	// it, as a lossy network would.
	Drop func(from, to netip.AddrPort) bool
}

// memLANBroadcast is the address that stands for "every Conn".
var memLANBroadcast = netip.MustParseAddrPort("255.255.255.255:9")

// NewMemLAN returns an empty broadcast domain.
func NewMemLAN() *MemLAN { return &MemLAN{conns: map[netip.AddrPort]*memPacketConn{}} }

// Broadcast is a Targets entry that reaches every Conn on the domain.
func (n *MemLAN) Broadcast() netip.AddrPort { return memLANBroadcast }

// Conn attaches a new packet conn at addr. It panics if addr is taken.
func (n *MemLAN) Conn(addr netip.AddrPort) net.PacketConn {
	c := &memPacketConn{n: n, addr: addr, in: make(chan memPacket, 256), done: make(chan struct{})}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns[addr] != nil {
		panic("room: MemLAN address in use: " + addr.String())
	}
	n.conns[addr] = c
	return c
}

func (n *MemLAN) send(from netip.AddrPort, to netip.AddrPort, p []byte) {
	n.mu.Lock()
	var dst []*memPacketConn
	if to == memLANBroadcast {
		for a, c := range n.conns {
			if a != from {
				dst = append(dst, c)
			}
		}
	} else if c := n.conns[to]; c != nil {
		dst = append(dst, c)
	}
	drop := n.Drop
	n.mu.Unlock()
	for _, c := range dst {
		if drop != nil && drop(from, c.addr) {
			continue
		}
		c.push(memPacket{from: from, b: append([]byte(nil), p...)})
	}
}

type memPacket struct {
	from netip.AddrPort
	b    []byte
}

type memPacketConn struct {
	n    *MemLAN
	addr netip.AddrPort
	in   chan memPacket
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
}

func (c *memPacketConn) push(p memPacket) {
	select {
	case <-c.done:
	case c.in <- p:
	default: // a full queue drops, as a socket buffer would
	}
}

func (c *memPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case p := <-c.in:
		return copy(b, p.b), net.UDPAddrFromAddrPort(p.from), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *memPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	c.n.send(c.addr, addrPortOf(addr), b)
	return len(b), nil
}

func (c *memPacketConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.n.mu.Lock()
		if c.n.conns[c.addr] == c {
			delete(c.n.conns, c.addr)
		}
		c.n.mu.Unlock()
	})
	return nil
}

func (c *memPacketConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.addr) }

func (c *memPacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *memPacketConn) SetWriteDeadline(time.Time) error { return nil }
