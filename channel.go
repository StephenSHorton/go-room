package room

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pion/datachannel"
)

// Data channel sizing. pion's SCTP caps one message at 64 KiB by default
// (sctp v1.12.0 defaultMaxMessageSize), so everything goes out in pieces of
// at most chunkSize. Writers block while more than highWater bytes are
// queued on a channel and resume once it drains to lowWater, so a big
// transfer can't queue without bound.
const (
	chunkSize = 16 << 10
	highWater = 1 << 20
	lowWater  = 256 << 10
	readBuf   = 64 << 10 // one detached Read returns one SCTP message
)

// ErrTooBig is returned for a message over the channel's cap.
var ErrTooBig = errors.New("room: message too big")

// flow is the high/low-water wait every writer shares.
type flow struct {
	dc   *datachannel.DataChannel
	low  chan struct{}
	done <-chan struct{}
}

func newFlow(dc *datachannel.DataChannel, done <-chan struct{}) *flow {
	f := &flow{dc: dc, low: make(chan struct{}, 1), done: done}
	dc.SetBufferedAmountLowThreshold(lowWater)
	dc.OnBufferedAmountLow(func() {
		select {
		case f.low <- struct{}{}:
		default:
		}
	})
	return f
}

// wait blocks while the channel's buffered amount is above highWater.
func (f *flow) wait(ctx context.Context) error {
	for f.dc.BufferedAmount() > highWater {
		select {
		case <-f.low:
		case <-ctx.Done():
			return ctx.Err()
		case <-f.done:
			return ErrClosed
		case <-time.After(50 * time.Millisecond): // belt and braces for a missed event
		}
	}
	return nil
}

// drain waits until everything written has left the send buffer (or ctx
// ends), so a Close right after the last Write doesn't race the data.
func (f *flow) drain(ctx context.Context) {
	for f.dc.BufferedAmount() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-f.done:
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Channel is a peer's one reliable, ordered message channel ("sync"). Each
// message is sent as a 4-byte big-endian length, then the bytes, cut into
// SCTP messages of at most 16 KiB and joined again on arrival.
type Channel struct {
	dc   *datachannel.DataChannel
	f    *flow
	max  int
	fail func(error) // breaks the peer

	sendMu sync.Mutex
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func newChannel(dc *datachannel.DataChannel, maxMsg int, fail func(error)) *Channel {
	c := &Channel{dc: dc, max: maxMsg, fail: fail, in: make(chan []byte, 16), done: make(chan struct{})}
	c.f = newFlow(dc, c.done)
	go c.readLoop()
	return c
}

// Send sends one whole message. It blocks while the channel is backed up.
// If ctx ends part way through a message the channel can't be resynced, so
// the peer is closed.
func (c *Channel) Send(ctx context.Context, msg []byte) error {
	if len(msg) > c.max {
		return fmt.Errorf("%w: %d bytes, cap %d", ErrTooBig, len(msg), c.max)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := c.closedErr(); err != nil {
		return err
	}
	first := true
	rest := msg
	for first || len(rest) > 0 {
		if err := c.f.wait(ctx); err != nil {
			if !first {
				c.fail(fmt.Errorf("room: send interrupted mid-message: %w", err))
			}
			if e := c.closedErr(); e != nil {
				return e
			}
			return err
		}
		var piece []byte
		if first {
			n := min(len(rest), chunkSize-4)
			piece = make([]byte, 4+n)
			binary.BigEndian.PutUint32(piece, uint32(len(msg)))
			copy(piece[4:], rest[:n])
			rest = rest[n:]
			first = false
		} else {
			n := min(len(rest), chunkSize)
			piece = rest[:n]
			rest = rest[n:]
		}
		if _, err := c.dc.Write(piece); err != nil {
			c.fail(err)
			if e := c.closedErr(); e != nil {
				return e
			}
			return err
		}
	}
	return nil
}

// Recv returns the next whole message.
func (c *Channel) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m := <-c.in:
		return m, nil
	default:
	}
	select {
	case m := <-c.in:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		select {
		case m := <-c.in:
			return m, nil
		default:
		}
		return nil, c.closedErr()
	}
}

func (c *Channel) readLoop() {
	buf := make([]byte, readBuf)
	var cur []byte
	want, inMsg := 0, false
	for {
		n, err := c.dc.Read(buf)
		if err != nil {
			c.fail(err)
			return
		}
		piece := buf[:n]
		if !inMsg {
			if n < 4 {
				c.fail(errors.New("room: short message header"))
				return
			}
			want = int(binary.BigEndian.Uint32(piece))
			if want > c.max {
				c.fail(fmt.Errorf("%w: peer sent %d bytes, cap %d", ErrTooBig, want, c.max))
				return
			}
			cur = make([]byte, 0, min(want, readBuf))
			piece = piece[4:]
			inMsg = true
		}
		if len(cur)+len(piece) > want {
			c.fail(errors.New("room: message longer than its header"))
			return
		}
		cur = append(cur, piece...)
		if len(cur) == want {
			select {
			case c.in <- cur:
			case <-c.done:
				return
			}
			cur, inMsg = nil, false
		}
	}
}

func (c *Channel) close(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
		_ = c.dc.Close()
	})
}

func (c *Channel) closedErr() error {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.err == nil {
			return ErrClosed
		}
		return c.err
	default:
		return nil
	}
}

// Stream is a byte stream over its own data channel, opened with
// Peer.OpenStream or received through Peer.OnStream. Writes go out in 16 KiB
// pieces under the same flow control as Channel. Close flushes what was
// written, then closes the channel; the other side's Read returns io.EOF.
// When the peer goes down, Read usually returns the peer's error instead,
// but a connection that dies at the wrong moment can still look like
// io.EOF: check lengths or hashes before trusting a stream as complete.
type Stream struct {
	label   string
	dc      *datachannel.DataChannel
	f       *flow
	release func()

	rmu  sync.Mutex
	rbuf []byte
	rest []byte

	wmu      sync.Mutex
	done     chan struct{}
	once     sync.Once
	abortErr error // set before done closes when the peer went away
}

func newStream(label string, dc *datachannel.DataChannel, release func()) *Stream {
	s := &Stream{label: label, dc: dc, release: release, done: make(chan struct{})}
	s.f = newFlow(dc, s.done)
	return s
}

// Label is the label the opener gave the stream.
func (s *Stream) Label() string { return s.label }

// Read reads bytes the other side wrote; io.EOF once it closed.
func (s *Stream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(s.rest) == 0 {
		if s.rbuf == nil {
			s.rbuf = make([]byte, readBuf)
		}
		n, err := s.dc.Read(s.rbuf)
		if err != nil {
			select {
			case <-s.done:
				if s.abortErr != nil {
					return 0, s.abortErr
				}
				return 0, io.EOF
			default:
			}
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		s.rest = s.rbuf[:n]
	}
	n := copy(p, s.rest)
	s.rest = s.rest[n:]
	return n, nil
}

// Write writes all of p, blocking while the channel is backed up.
func (s *Stream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		if err := s.f.wait(context.Background()); err != nil {
			return written, err
		}
		n := min(len(p), chunkSize)
		if _, err := s.dc.Write(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close flushes what was written (up to 30 s) and closes the stream.
func (s *Stream) Close() error {
	var err error
	s.once.Do(func() {
		s.wmu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		s.f.drain(ctx)
		cancel()
		s.wmu.Unlock()
		close(s.done)
		err = s.dc.Close()
		if s.release != nil {
			s.release()
		}
	})
	return err
}

// abort closes the stream without flushing (its peer went away); a Read
// after it returns err rather than io.EOF.
func (s *Stream) abort(err error) {
	s.once.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		s.abortErr = err
		close(s.done)
		_ = s.dc.Close()
		if s.release != nil {
			s.release()
		}
	})
}
