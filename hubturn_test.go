package room

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Two members that can reach each other only through the hub's TURN: they
// signal over a real hub on 127.0.0.1, take their relay credentials from it
// (HubClient.TURN through a Relay, as Irori does), run relay-only ICE, and
// the TURN server keeps its default peer filter, which admits only
// addresses it relays itself. The selected pair is relay on both ends, over
// UDP and over TURN-over-TCP on the hub's own port.
func TestMeshRelayOnlyThroughHubTURN(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			ln := listenLoopback(t)
			hubLn, turnLn := SplitTCP(ln)
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tcfg := TURNConfig{UDP: udp, TCP: turnLn, RelayIP: netip.MustParseAddr("127.0.0.1")}
			_, _ = rand.Read(tcfg.Key[:])
			ts, err := NewTURN(tcfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(ts.Close)
			th := newTestHubOn(t, hubLn, func(c *HubConfig) { c.TURN = ts })
			th.addr = ln.Addr().String()

			// UDP sits on its own port here; TURN-over-TCP shares the hub's.
			uris := func(addr string) []string {
				if transport == "udp" {
					return []string{"turn:" + udp.LocalAddr().String() + "?transport=udp"}
				}
				return []string{"turn:" + addr + "?transport=tcp"}
			}
			s := testSecret(t)
			openOn(t, s, "srv", th.hub.Local())
			member := func(id string) *node {
				c := th.memberWith(t, id, func(cfg *HubDialConfig) { cfg.TURNURIs = uris })
				waitFor(t, id+" connected", c.Up)
				r := NewRelay(RelayConfig{Fetch: c.TURN, Logf: t.Logf}, id, nil)
				r.Start()
				t.Cleanup(r.Stop)
				waitFor(t, id+" relay credentials", func() bool { return r.Status().State == RelayOK })
				sig, err := Open(s, id, SignalOptions{}, c.Carrier())
				if err != nil {
					t.Fatal(err)
				}
				return newNodeOn(t, sig, id, nodeOpts{ice: r.TURN, relay: true})
			}
			a, b := member("dev-a"), member("dev-b")
			// The sub frames race the first want; Connect again until it lands.
			go func() {
				for range 100 {
					if b.mesh.Peer("dev-a") != nil {
						return
					}
					b.mesh.Connect("dev-a")
					time.Sleep(100 * time.Millisecond)
				}
			}()
			pb := waitUp(t, b)
			pa := waitUp(t, a)
			for _, p := range []*Peer{pa, pb} {
				local, remote := selectedTypes(t, p)
				if local != webrtc.ICECandidateTypeRelay || remote != webrtc.ICECandidateTypeRelay {
					t.Fatalf("selected pair %s/%s, want relay/relay", local, remote)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			exchange(t, ctx, pa, pb)
		})
	}
}

// selectedTypes is the candidate types of p's selected ICE pair.
func selectedTypes(t *testing.T, p *Peer) (local, remote webrtc.ICECandidateType) {
	t.Helper()
	var pair *webrtc.ICECandidatePair
	waitFor(t, "a selected pair", func() bool {
		if p.pc == nil || p.pc.SCTP() == nil || p.pc.SCTP().Transport() == nil {
			return false
		}
		pr, err := p.pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		pair = pr
		return err == nil && pr != nil
	})
	return pair.Local.Typ, pair.Remote.Typ
}
