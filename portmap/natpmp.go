package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jackpal/gateway"
)

// NAT-PMP (RFC 6886): three requests over UDP to the gateway, version 0.
//
//	external address: op 0           -> op 128, result, epoch, address
//	map UDP / TCP:    op 1 / 2, internal port, suggested external, lifetime
//	                                 -> op 129 / 130, result, epoch, internal, external, lifetime
//
// A lifetime of 0 removes the mapping. Requests are retried from 250 ms,
// doubling, as the RFC says, bounded by natpmpTries and the context.

// NATPMPPort is the gateway port NAT-PMP uses.
const NATPMPPort = 5351

var (
	natpmpFirstWait = 250 * time.Millisecond
	natpmpTries     = 5
)

// NATPMP is a Gateway speaking NAT-PMP to gw (the app: the default gateway
// on NATPMPPort; tests: a fake on 127.0.0.1).
func NATPMP(gw netip.AddrPort) Gateway { return &natpmpGateway{gw: gw} }

type natpmpGateway struct{ gw netip.AddrPort }

func (g *natpmpGateway) Method() string { return "natpmp" }

// NAT-PMP result codes.
var natpmpResults = map[uint16]string{
	1: "unsupported version",
	2: "not authorized or refused",
	3: "network failure",
	4: "out of resources",
	5: "unsupported opcode",
}

func (g *natpmpGateway) call(ctx context.Context, req []byte, respLen int) ([]byte, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(g.gw))
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Now()) })
	defer stop()
	wait := natpmpFirstWait
	buf := make([]byte, 64)
	for try := 0; try < natpmpTries; try++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		_ = c.SetReadDeadline(time.Now().Add(wait))
		for {
			n, err := c.Read(buf)
			if err != nil {
				break // timeout: send again
			}
			if n < respLen || buf[0] != 0 || buf[1] != 128+req[1] {
				continue // not the answer to this request
			}
			if rc := binary.BigEndian.Uint16(buf[2:4]); rc != 0 {
				msg := natpmpResults[rc]
				if msg == "" {
					msg = fmt.Sprintf("result %d", rc)
				}
				return nil, errors.New("natpmp: " + msg)
			}
			return append([]byte(nil), buf[:n]...), nil
		}
		wait *= 2
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("natpmp: no answer from the gateway")
}

func (g *natpmpGateway) ExternalIP(ctx context.Context) (netip.Addr, error) {
	resp, err := g.call(ctx, []byte{0, 0}, 12)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte(resp[8:12])), nil
}

func natpmpOp(proto string) (byte, error) {
	switch proto {
	case "udp":
		return 1, nil
	case "tcp":
		return 2, nil
	}
	return 0, fmt.Errorf("natpmp: unknown protocol %q", proto)
}

func (g *natpmpGateway) mapReq(ctx context.Context, p Port, life time.Duration) (Port, time.Duration, error) {
	op, err := natpmpOp(p.Proto)
	if err != nil {
		return Port{}, 0, err
	}
	req := make([]byte, 12)
	req[1] = op
	binary.BigEndian.PutUint16(req[4:6], p.Internal)
	binary.BigEndian.PutUint16(req[6:8], p.External)
	binary.BigEndian.PutUint32(req[8:12], uint32(life/time.Second))
	resp, err := g.call(ctx, req, 16)
	if err != nil {
		return Port{}, 0, err
	}
	got := Port{Proto: p.Proto, Internal: binary.BigEndian.Uint16(resp[8:10]), External: binary.BigEndian.Uint16(resp[10:12])}
	return got, time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second, nil
}

// Map asks for p; the router picks another external port itself if the one
// asked for is taken, so a conflict never surfaces here.
func (g *natpmpGateway) Map(ctx context.Context, p Port, life time.Duration) (Port, time.Duration, error) {
	if p.External == 0 {
		p.External = p.Internal
	}
	if life < time.Second {
		life = time.Second
	}
	got, granted, err := g.mapReq(ctx, p, life)
	if err != nil {
		return Port{}, 0, err
	}
	if granted == 0 {
		return Port{}, 0, errors.New("natpmp: the gateway granted no lifetime")
	}
	return got, granted, nil
}

func (g *natpmpGateway) Unmap(ctx context.Context, p Port) error {
	_, _, err := g.mapReq(ctx, Port{Proto: p.Proto, Internal: p.Internal}, 0)
	return err
}

// discoverDefault is Config.Discover's default: IGDs by SSDP, then NAT-PMP
// at the default gateway.
func discoverDefault(desc string) func(ctx context.Context) ([]Gateway, error) {
	return func(ctx context.Context) ([]Gateway, error) {
		gws := discoverUPnP(ctx, desc)
		ip, err := gateway.DiscoverGateway()
		if err == nil {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
				gws = append(gws, NATPMP(netip.AddrPortFrom(a.Unmap(), NATPMPPort)))
			}
		}
		if len(gws) == 0 && err != nil {
			return nil, err
		}
		return gws, nil
	}
}
