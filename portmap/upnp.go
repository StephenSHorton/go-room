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
	"github.com/huin/goupnp/httpu"
	"github.com/huin/goupnp/soap"
	"github.com/huin/goupnp/ssdp"
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
	GetSpecificPortMappingEntryCtx(ctx context.Context, remoteHost string, extPort uint16, proto string) (
		intPort uint16, intClient string, enabled bool, desc string, lease uint32, err error)
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

// UnmapStale removes a mapping an earlier run left (a crash leaves a
// permanent one forever), only if the router says it points at this
// machine and carries this app's description.
func (g *upnpGateway) UnmapStale(ctx context.Context, p Port) error {
	_, client, _, desc, _, err := g.c.GetSpecificPortMappingEntryCtx(ctx, "", p.External, upnpProto(p.Proto))
	if err != nil {
		return err
	}
	if client != g.local || desc != g.desc {
		return nil // someone else's
	}
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
// app only, never tests), sent from the interface that reaches gw, the
// default gateway. Only an IGD at gw itself is kept, and only its
// description is fetched: any host on the LAN can answer SSDP, and one that
// isn't the router could otherwise take the mapping and name any address
// as the "external" one, or make this machine fetch any URL.
func discoverUPnP(ctx context.Context, desc string, gw netip.Addr) []Gateway {
	if !gw.IsValid() {
		return nil
	}
	local, err := localAddrFor(&url.URL{Host: net.JoinHostPort(gw.String(), "1900")})
	if err != nil {
		return nil
	}
	hc, err := httpu.NewHTTPUClientAddr(local)
	if err != nil {
		return nil
	}
	defer func() { _ = hc.Close() }()
	var out []Gateway
	seen := map[string]bool{}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:2", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"} {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		resps, err := ssdp.RawSearch(sctx, hc, st, 3)
		cancel()
		if err != nil {
			continue
		}
		for _, r := range resps {
			loc, err := r.Location()
			if err != nil || seen[loc.String()] || !atGateway(loc, gw) {
				continue
			}
			seen[loc.String()] = true
			root, err := goupnp.DeviceByURLCtx(ctx, loc)
			if err != nil {
				continue
			}
			out = append(out, gatewaysFrom(root, loc, local, desc)...)
		}
	}
	return out
}

// atGateway reports whether an SSDP answer's description URL is on the
// default gateway's own address.
func atGateway(loc *url.URL, gw netip.Addr) bool {
	if loc == nil || (loc.Scheme != "http" && loc.Scheme != "https") {
		return false
	}
	a, err := netip.ParseAddr(loc.Hostname())
	return err == nil && gw.IsValid() && a.Unmap() == gw.Unmap()
}
