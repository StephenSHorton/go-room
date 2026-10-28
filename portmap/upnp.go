package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

// UPnP error codes (IGD v1 and v2 WANIPConnection).
const (
	upnpConflict      = 718 // ConflictInMappingEntry
	upnpOnlyPermanent = 725 // OnlyPermanentLeasesSupported
)

// igdClient is what WANIPConnection1, WANIPConnection2 and
// WANPPPConnection1 have in common.
type igdClient interface {
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	AddPortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string, intPort uint16,
		intClient string, enabled bool, desc string, lease uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string) error
}

type upnpGateway struct {
	c     igdClient
	local string // this machine's address on the router's network
	desc  string
	kind  string
}

func (g *upnpGateway) Method() string { return "upnp" }

func (g *upnpGateway) ExternalIP(ctx context.Context) (netip.Addr, error) {
	s, err := g.c.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("router's external address %q: %w", s, err)
	}
	return a, nil
}

func (g *upnpGateway) Map(ctx context.Context, p Port, life time.Duration) (Port, time.Duration, error) {
	if p.External == 0 {
		p.External = p.Internal
	}
	lease := uint32(life / time.Second)
	err := g.c.AddPortMappingCtx(ctx, "", p.External, upnpProto(p.Proto), p.Internal, g.local, true, g.desc, lease)
	if code := upnpCode(err); code == upnpOnlyPermanent {
		lease = 0
		err = g.c.AddPortMappingCtx(ctx, "", p.External, upnpProto(p.Proto), p.Internal, g.local, true, g.desc, 0)
	}
	if code := upnpCode(err); code == upnpConflict {
		return Port{}, 0, ErrConflict
	}
	if err != nil {
		return Port{}, 0, err
	}
	return p, time.Duration(lease) * time.Second, nil
}

func (g *upnpGateway) Unmap(ctx context.Context, p Port) error {
	return g.c.DeletePortMappingCtx(ctx, "", p.External, upnpProto(p.Proto))
}

func upnpProto(p string) string { return strings.ToUpper(p) }

func upnpCode(err error) int {
	var f *soap.SOAPFaultError
	if errors.As(err, &f) {
		return f.Detail.UPnPError.Errorcode
	}
	return 0
}

// UPnP reads an IGD's description at descURL and returns a Gateway for each
// WAN connection service it has: WANIPConnection:2 first, then
// WANIPConnection:1, then WANPPPConnection:1. No SSDP: the URL is known
// (tests point it at a fake IGD on 127.0.0.1).
func UPnP(ctx context.Context, descURL string) ([]Gateway, error) {
	loc, err := url.Parse(descURL)
	if err != nil {
		return nil, err
	}
	root, err := goupnp.DeviceByURLCtx(ctx, loc)
	if err != nil {
		return nil, err
	}
	local, err := localAddrFor(loc)
	if err != nil {
		return nil, err
	}
	return gatewaysFrom(root, loc, local, ""), nil
}

func gatewaysFrom(root *goupnp.RootDevice, loc *url.URL, local, desc string) []Gateway {
	if desc == "" {
		desc = "go-room"
	}
	var out []Gateway
	if cs, err := internetgateway2.NewWANIPConnection2ClientsFromRootDevice(root, loc); err == nil {
		for _, c := range cs {
			out = append(out, &upnpGateway{c: c, local: local, desc: desc, kind: "WANIPConnection:2"})
		}
	}
	if cs, err := internetgateway2.NewWANIPConnection1ClientsFromRootDevice(root, loc); err == nil {
		for _, c := range cs {
			out = append(out, &upnpGateway{c: c, local: local, desc: desc, kind: "WANIPConnection:1"})
		}
	}
	if cs, err := internetgateway2.NewWANPPPConnection1ClientsFromRootDevice(root, loc); err == nil {
		for _, c := range cs {
			out = append(out, &upnpGateway{c: c, local: local, desc: desc, kind: "WANPPPConnection:1"})
		}
	}
	return out
}

// localAddrFor is the address this machine uses to reach the router at loc:
// a connected UDP socket sends nothing, it only picks the route.
func localAddrFor(loc *url.URL) (string, error) {
	host := loc.Hostname()
	port := loc.Port()
	if port == "" {
		port = "80"
	}
	c, err := net.Dial("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	return addrOf(c.LocalAddr()).String(), nil
}

func addrOf(a net.Addr) netip.Addr {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap.Addr()
}

// discoverUPnP finds IGDs on the network by SSDP (a multicast search: the
// app only, never tests).
func discoverUPnP(ctx context.Context, desc string) []Gateway {
	var out []Gateway
	seen := map[string]bool{}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:2", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"} {
		found, err := goupnp.DiscoverDevicesCtx(ctx, st)
		if err != nil {
			continue
		}
		for _, d := range found {
			if d.Err != nil || d.Root == nil || seen[d.Location.String()] {
				continue
			}
			seen[d.Location.String()] = true
			local := ""
			if d.LocalAddr != nil {
				local = d.LocalAddr.String()
			} else if l, err := localAddrFor(d.Location); err == nil {
				local = l
			}
			out = append(out, gatewaysFrom(d.Root, d.Location, local, desc)...)
		}
	}
	return out
}
