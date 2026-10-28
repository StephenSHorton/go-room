// Package portmap asks the home router to forward ports to this machine,
// over UPnP-IGD (through goupnp) or NAT-PMP (RFC 6886, go-room's own
// client), so devices away from home can reach a home server. It keeps the
// mappings renewed and removes them on Close.
//
// Discovery (SSDP for an IGD at the default gateway, then NAT-PMP there)
// runs only in the app; tests hand Start their own gateways, pointed at fakes on
// 127.0.0.1.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Port is one mapping: Proto "tcp" or "udp", the port on this machine, and
// the port on the router's external address (0 = ask for Internal).
type Port struct {
	Proto    string `json:"proto"`
	Internal uint16 `json:"internal"`
	External uint16 `json:"external"`
}

// Gateway is one router protocol endpoint.
type Gateway interface {
	// Method is "upnp" or "natpmp".
	Method() string
	// ExternalIP is the router's own external address.
	ExternalIP(ctx context.Context) (netip.Addr, error)
	// Map asks for p for life and returns the mapping as granted (the
	// external port may differ) and its lifetime (0 = permanent).
	Map(ctx context.Context, p Port, life time.Duration) (got Port, granted time.Duration, err error)
	// Unmap removes a mapping Map made.
	Unmap(ctx context.Context, p Port) error
}

// staleUnmapper is a Gateway that can remove a mapping an earlier run of
// this app left, after checking it is this machine's own (UPnP; NAT-PMP
// mappings always expire).
type staleUnmapper interface {
	UnmapStale(ctx context.Context, p Port) error
}

// ErrConflict is Map's error when the external port is taken by another
// mapping; the Mapper then asks for another one.
var ErrConflict = errors.New("portmap: external port already mapped")

// Mapping states.
const (
	StateNone    = "none"    // not started, or closed
	StatePending = "pending" // finding the router and mapping
	StateOK      = "ok"      // every port is mapped
	StateFailed  = "failed"  // no router answered, or it refused (Detail says why)
)

// Status is how mapping is doing.
type Status struct {
	State    string     `json:"state"`
	Method   string     `json:"method,omitempty"`
	External netip.Addr `json:"external,omitzero"` // the router's external address
	Ports    []Port     `json:"ports,omitempty"`   // as granted (External may differ from Internal)
	CGNAT    bool       `json:"cgnat,omitempty"`   // External is in 100.64.0.0/10 or private space
	Detail   string     `json:"detail,omitempty"`
}

func (s Status) equal(o Status) bool {
	return s.State == o.State && s.Method == o.Method && s.External == o.External &&
		slices.Equal(s.Ports, o.Ports) && s.CGNAT == o.CGNAT && s.Detail == o.Detail
}

// Config sets up a Mapper.
type Config struct {
	// Ports to map (Irori: TCP N and UDP N).
	Ports []Port
	// Discover finds gateways, tried in order. nil: SSDP for an IGD at the
	// default gateway (an answer from any other host is ignored), then
	// NAT-PMP there.
	Discover func(ctx context.Context) ([]Gateway, error)
	// Lifetime asked for (default 1 h); renewed at half of what was granted.
	Lifetime time.Duration
	// Description is the UPnP mapping description (Irori: "irori").
	Description string
	// Stale lists mappings an earlier run may have left on the router
	// (Proto and External): a crash, a kill or a power cut skips Close, and
	// a permanent UPnP lease then stays forever. Each is removed from the
	// first gateway mapped on, if it still points at this machine with
	// this Description.
	Stale []Port
	// OnChange, when set, gets each new Status.
	OnChange func(Status)
	// Logf, when set, gets diagnostics.
	Logf func(format string, args ...any)
}

// Timing, as variables so tests can run fast.
var (
	retryFailed = 5 * time.Minute  // after nothing could be mapped
	recheck     = 30 * time.Minute // a permanent mapping is asked for again this often
	ipPoll      = 3 * time.Minute  // the router's external address is re-read this often
	minRenew    = time.Second
	callTimeout = 10 * time.Second
	conflictTry = 4 // other external ports tried after a conflict
)

// CGNAT reports whether a router's external address is shared: in
// 100.64.0.0/10 (RFC 6598) or private space (a router behind a router).
func CGNAT(a netip.Addr) bool {
	a = a.Unmap()
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a) || a.IsPrivate() || a.IsLoopback()
}

// Mapper keeps the mappings up.
type Mapper struct {
	cfg  Config
	quit chan struct{}
	done chan struct{}

	mu        sync.Mutex
	status    Status
	gw        Gateway
	mapped    []Port
	staleDone bool
}

// Start begins mapping in the background.
func Start(cfg Config) *Mapper {
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = time.Hour
	}
	if cfg.Description == "" {
		cfg.Description = "go-room"
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Discover == nil {
		cfg.Discover = discoverDefault(cfg.Description)
	}
	m := &Mapper{cfg: cfg, quit: make(chan struct{}), done: make(chan struct{}), status: Status{State: StatePending}}
	go m.loop()
	return m
}

// Status returns the current status.
func (m *Mapper) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Ports = slices.Clone(s.Ports)
	return s
}

// Close stops renewing and removes the mappings.
func (m *Mapper) Close() {
	select {
	case <-m.quit:
	default:
		close(m.quit)
	}
	<-m.done
}

func (m *Mapper) set(s Status) {
	m.mu.Lock()
	changed := !m.status.equal(s)
	m.status = s
	m.mu.Unlock()
	if changed && m.cfg.OnChange != nil {
		m.cfg.OnChange(s)
	}
}

func (m *Mapper) ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	go func() {
		select {
		case <-m.quit:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (m *Mapper) loop() {
	defer close(m.done)
	defer m.unmapAll()
	m.set(Status{State: StatePending})
	for {
		next := time.Now().Add(m.cycle())
		// Between renewals, the external address is re-read: an ISP can
		// change it at any time, and devices away from home dial it.
		for {
			d := time.Until(next)
			if d <= 0 {
				break
			}
			select {
			case <-m.quit:
				return
			case <-time.After(min(d, ipPoll)):
			}
			if time.Until(next) > 0 {
				m.recheckIP()
			}
		}
	}
}

// recheckIP re-reads the external address on the gateway in use and
// updates the status when it changed.
func (m *Mapper) recheckIP() {
	m.mu.Lock()
	g, st := m.gw, m.status
	m.mu.Unlock()
	if g == nil || st.State != StateOK {
		return
	}
	ctx, cancel := m.ctx()
	ext, err := g.ExternalIP(ctx)
	cancel()
	if err != nil || ext.Unmap() == st.External {
		return
	}
	m.cfg.Logf("portmap: the router's external address changed to %s", ext.Unmap())
	m.mu.Lock()
	if m.gw != g {
		m.mu.Unlock()
		return
	}
	st = m.status
	st.External = ext.Unmap()
	st.CGNAT = CGNAT(st.External)
	st.Ports = slices.Clone(st.Ports)
	m.mu.Unlock()
	m.set(st)
}

// unmapStale removes Config.Stale from the first gateway that can, once
// per Mapper.
func (m *Mapper) unmapStale(g Gateway) {
	su, ok := g.(staleUnmapper)
	if !ok {
		return
	}
	m.mu.Lock()
	done := m.staleDone
	m.staleDone = true
	m.mu.Unlock()
	if done {
		return
	}
	for _, p := range m.cfg.Stale {
		if p.External == 0 {
			continue
		}
		ctx, cancel := m.ctx()
		if err := su.UnmapStale(ctx, p); err != nil {
			m.cfg.Logf("portmap: remove an old %s %d: %v", p.Proto, p.External, err)
		}
		cancel()
	}
}

// cycle maps (or renews) everything once and says when to run again.
func (m *Mapper) cycle() time.Duration {
	m.mu.Lock()
	gw := m.gw
	m.mu.Unlock()
	if gw != nil {
		// Renew on the gateway that worked, asking for what was granted.
		wait, err := m.mapOn(gw, true)
		if err == nil {
			return wait
		}
		m.cfg.Logf("portmap: renew on %s: %v", gw.Method(), err)
		m.unmapAll()
	}
	ctx, cancel := m.ctx()
	gws, err := m.cfg.Discover(ctx)
	cancel()
	if err != nil && len(gws) == 0 {
		m.set(Status{State: StateFailed, Detail: "no router answered: " + err.Error()})
		return retryFailed
	}
	if len(gws) == 0 {
		m.set(Status{State: StateFailed, Detail: "no router answered UPnP or NAT-PMP"})
		return retryFailed
	}
	var errs []string
	for _, g := range gws {
		wait, err := m.mapOn(g, false)
		if err == nil {
			return wait
		}
		errs = append(errs, g.Method()+": "+err.Error())
		m.unmapAll()
	}
	m.set(Status{State: StateFailed, Detail: fmt.Sprint("the router refused: ", errs)})
	return retryFailed
}

// mapOn maps every port on g; on success it records g and the status.
func (m *Mapper) mapOn(g Gateway, renew bool) (time.Duration, error) {
	want := slices.Clone(m.cfg.Ports)
	if renew {
		m.mu.Lock()
		want = slices.Clone(m.mapped)
		m.mu.Unlock()
	}
	if !renew {
		m.unmapStale(g)
	}
	var got []Port
	shortest := time.Duration(0)
	for _, p := range want {
		mp, granted, err := m.mapOne(g, p)
		if err != nil {
			m.mu.Lock()
			if !renew {
				m.gw, m.mapped = g, got // so unmapAll removes what this attempt made
			}
			m.mu.Unlock()
			return 0, err
		}
		got = append(got, mp)
		if granted > 0 && (shortest == 0 || granted < shortest) {
			shortest = granted
		}
	}
	ctx, cancel := m.ctx()
	ext, err := g.ExternalIP(ctx)
	cancel()
	st := Status{State: StateOK, Method: g.Method(), Ports: got}
	if err != nil {
		st.Detail = "the router didn't say its external address: " + err.Error()
	} else {
		st.External = ext.Unmap()
		st.CGNAT = CGNAT(st.External)
	}
	m.mu.Lock()
	m.gw, m.mapped = g, got
	m.mu.Unlock()
	m.set(st)
	if shortest == 0 {
		return recheck, nil
	}
	return max(shortest/2, minRenew), nil
}

// mapOne maps one port, trying other external ports after a conflict.
func (m *Mapper) mapOne(g Gateway, p Port) (Port, time.Duration, error) {
	try := p
	for i := 0; ; i++ {
		ctx, cancel := m.ctx()
		got, granted, err := g.Map(ctx, try, m.cfg.Lifetime)
		cancel()
		if err == nil {
			return got, granted, nil
		}
		if !errors.Is(err, ErrConflict) || i >= conflictTry {
			return Port{}, 0, err
		}
		try.External = uint16(20000 + rand.IntN(10000))
		m.cfg.Logf("portmap: %s %d taken on the router; trying %d", p.Proto, p.External, try.External)
	}
}

func (m *Mapper) unmapAll() {
	m.mu.Lock()
	g, ports := m.gw, m.mapped
	m.gw, m.mapped = nil, nil
	m.mu.Unlock()
	if g == nil {
		return
	}
	for _, p := range ports {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := g.Unmap(ctx, p); err != nil {
			m.cfg.Logf("portmap: unmap %s %d: %v", p.Proto, p.External, err)
		}
		cancel()
	}
	select {
	case <-m.quit:
		m.set(Status{State: StateNone})
	default:
	}
}
