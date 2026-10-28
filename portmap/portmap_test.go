package portmap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Both fakes run on 127.0.0.1: an IGD over httptest, and a NAT-PMP gateway
// on a UDP socket. Nothing does SSDP or reads the real default gateway.

// --- fake UPnP IGD --------------------------------------------------------

type fakeIGD struct {
	srv *httptest.Server

	mu            sync.Mutex
	external      string
	maps          map[string]uint32 // "TCP:24817" -> lease
	taken         map[string]bool   // external ports held by someone else
	onlyPermanent bool
	refuse        bool
	adds          int
}

const igdDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>fake</friendlyName>
  <UDN>uuid:fake-igd</UDN>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <UDN>uuid:fake-wan</UDN>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <UDN>uuid:fake-wanconn</UDN>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
     <SCPDURL>/scpd.xml</SCPDURL>
     <controlURL>/ctl</controlURL>
     <eventSubURL>/evt</eventSubURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`

func newFakeIGD(t *testing.T, external string) *fakeIGD {
	f := &fakeIGD{external: external, maps: map[string]uint32{}, taken: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, igdDesc)
	})
	mux.HandleFunc("/ctl", f.control)
	f.srv = httptest.NewServer(mux) // 127.0.0.1
	t.Cleanup(f.srv.Close)
	return f
}

var soapArg = regexp.MustCompile(`<(New[A-Za-z]+)>([^<]*)</`)

func (f *fakeIGD) control(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	action := r.Header.Get("SOAPAction")
	action = strings.Trim(action[strings.LastIndex(action, "#")+1:], `"`)
	args := map[string]string{}
	for _, m := range soapArg.FindAllStringSubmatch(string(body), -1) {
		args[m[1]] = m[2]
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := args["NewProtocol"] + ":" + args["NewExternalPort"]
	switch action {
	case "GetExternalIPAddress":
		soapOK(w, action, "<NewExternalIPAddress>"+f.external+"</NewExternalIPAddress>")
	case "AddPortMapping":
		f.adds++
		lease, _ := strconv.Atoi(args["NewLeaseDuration"])
		switch {
		case f.refuse:
			soapFault(w, 606, "Action not authorized")
		case f.taken[key]:
			soapFault(w, 718, "ConflictInMappingEntry")
		case f.onlyPermanent && lease != 0:
			soapFault(w, 725, "OnlyPermanentLeasesSupported")
		default:
			f.maps[key] = uint32(lease)
			soapOK(w, action, "")
		}
	case "DeletePortMapping":
		delete(f.maps, key)
		soapOK(w, action, "")
	default:
		soapFault(w, 401, "Invalid Action")
	}
}

func soapOK(w http.ResponseWriter, action, inner string) {
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%sResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">%s</u:%sResponse></s:Body></s:Envelope>`, action, inner, action)
}

func soapFault(w http.ResponseWriter, code int, desc string) {
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, desc)
}

func (f *fakeIGD) mapped() map[string]uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint32{}
	for k, v := range f.maps {
		out[k] = v
	}
	return out
}

func (f *fakeIGD) gateways(t *testing.T) []Gateway {
	t.Helper()
	gws, err := UPnP(context.Background(), f.srv.URL+"/desc.xml")
	if err != nil {
		t.Fatal(err)
	}
	if len(gws) != 1 || gws[0].Method() != "upnp" {
		t.Fatalf("gateways %v", gws)
	}
	return gws
}

// --- fake NAT-PMP gateway -------------------------------------------------

type fakePMP struct {
	conn *net.UDPConn

	mu       sync.Mutex
	external [4]byte
	maps     map[string]uint16 // "udp:24817" -> external
	lifetime uint32            // granted (0: grant what was asked)
	silent   bool
	result   uint16
	reqs     int
}

func newFakePMP(t *testing.T, external string) *fakePMP {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePMP{conn: c, external: netip.MustParseAddr(external).As4(), maps: map[string]uint16{}}
	t.Cleanup(func() { _ = c.Close() })
	go f.serve()
	return f
}

func (f *fakePMP) addr() netip.AddrPort { return f.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (f *fakePMP) serve() {
	buf := make([]byte, 64)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.reqs++
		if f.silent || n < 2 || buf[0] != 0 {
			f.mu.Unlock()
			continue
		}
		op := buf[1]
		var resp []byte
		switch {
		case op == 0:
			resp = make([]byte, 12)
			copy(resp[8:], f.external[:])
		case (op == 1 || op == 2) && n >= 12:
			proto := map[byte]string{1: "udp", 2: "tcp"}[op]
			internal := binary.BigEndian.Uint16(buf[4:6])
			ext := binary.BigEndian.Uint16(buf[6:8])
			life := binary.BigEndian.Uint32(buf[8:12])
			key := proto + ":" + strconv.Itoa(int(internal))
			if life == 0 {
				delete(f.maps, key)
				ext = 0
			} else {
				if f.lifetime != 0 {
					life = f.lifetime
				}
				f.maps[key] = ext
			}
			resp = make([]byte, 16)
			binary.BigEndian.PutUint16(resp[8:10], internal)
			binary.BigEndian.PutUint16(resp[10:12], ext)
			binary.BigEndian.PutUint32(resp[12:16], life)
		default:
			f.mu.Unlock()
			continue
		}
		resp[1] = 128 + op
		binary.BigEndian.PutUint16(resp[2:4], f.result)
		f.mu.Unlock()
		_, _ = f.conn.WriteToUDPAddrPort(resp, from)
	}
}

func (f *fakePMP) mapped() map[string]uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint16{}
	for k, v := range f.maps {
		out[k] = v
	}
	return out
}

// --- tests ----------------------------------------------------------------

var ports = []Port{{Proto: "tcp", Internal: 24817}, {Proto: "udp", Internal: 24817}}

func fast(t *testing.T) {
	oldR, oldW, oldMin := retryFailed, natpmpFirstWait, minRenew
	retryFailed, natpmpFirstWait, minRenew = 50*time.Millisecond, 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { retryFailed, natpmpFirstWait, minRenew = oldR, oldW, oldMin })
}

func waitState(t *testing.T, m *Mapper, state string) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := m.Status()
		if s.State == state {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %q (%s), want %q", s.State, s.Detail, state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUPnPMapper(t *testing.T) {
	fast(t)
	f := newFakeIGD(t, "203.0.113.9")
	gws := f.gateways(t)
	var changes []Status
	var mu sync.Mutex
	m := Start(Config{Ports: ports, Discover: func(context.Context) ([]Gateway, error) { return gws, nil },
		Description: "irori", OnChange: func(s Status) { mu.Lock(); changes = append(changes, s); mu.Unlock() }})
	s := waitState(t, m, StateOK)
	if s.Method != "upnp" || s.External != netip.MustParseAddr("203.0.113.9") || s.CGNAT || len(s.Ports) != 2 ||
		s.Ports[0].External != 24817 {
		t.Fatalf("status %+v", s)
	}
	got := f.mapped()
	if got["TCP:24817"] != 3600 || got["UDP:24817"] != 3600 {
		t.Fatalf("mappings %v", got)
	}
	m.Close()
	if len(f.mapped()) != 0 {
		t.Fatalf("Close left %v", f.mapped())
	}
	if m.Status().State != StateNone {
		t.Fatal("status after Close")
	}
	mu.Lock()
	n := len(changes)
	mu.Unlock()
	if n < 2 {
		t.Fatalf("OnChange %d times", n)
	}
}

func TestUPnPConflictAndPermanent(t *testing.T) {
	fast(t)
	f := newFakeIGD(t, "100.64.3.4")
	f.taken["TCP:24817"] = true
	f.onlyPermanent = true
	gws := f.gateways(t)
	m := Start(Config{Ports: ports, Discover: func(context.Context) ([]Gateway, error) { return gws, nil }})
	defer m.Close()
	s := waitState(t, m, StateOK)
	if !s.CGNAT {
		t.Fatal("100.64/10 not reported as CGNAT")
	}
	if s.Ports[0].External == 24817 || s.Ports[0].External < 20000 || s.Ports[0].External > 29999 || s.Ports[1].External != 24817 {
		t.Fatalf("ports after a conflict %+v", s.Ports)
	}
	for k, lease := range f.mapped() {
		if lease != 0 {
			t.Fatalf("%s lease %d, want permanent", k, lease)
		}
	}
}

func TestNATPMP(t *testing.T) {
	fast(t)
	f := newFakePMP(t, "198.51.100.7")
	g := NATPMP(f.addr())
	ctx := context.Background()
	ip, err := g.ExternalIP(ctx)
	if err != nil || ip != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("external %v %v", ip, err)
	}
	got, life, err := g.Map(ctx, Port{Proto: "udp", Internal: 24817}, time.Hour)
	if err != nil || got.External != 24817 || life != time.Hour {
		t.Fatalf("map %+v %v %v", got, life, err)
	}
	if err := g.Unmap(ctx, got); err != nil || len(f.mapped()) != 0 {
		t.Fatalf("unmap %v %v", err, f.mapped())
	}
	f.mu.Lock()
	f.result = 2
	f.mu.Unlock()
	if _, _, err := g.Map(ctx, Port{Proto: "tcp", Internal: 1}, time.Hour); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("refusal: %v", err)
	}
	f.mu.Lock()
	f.result, f.silent = 0, true
	f.mu.Unlock()
	if _, err := g.ExternalIP(ctx); err == nil {
		t.Fatal("no answer, no error")
	}
}

// UPnP refused, NAT-PMP answers: the Mapper falls through, and renews at
// half the granted lifetime.
func TestMapperFallsBackAndRenews(t *testing.T) {
	fast(t)
	igd := newFakeIGD(t, "203.0.113.9")
	igd.refuse = true
	pmp := newFakePMP(t, "203.0.113.9")
	pmp.mu.Lock()
	pmp.lifetime = 1 // second
	pmp.mu.Unlock()
	gws := append(igd.gateways(t), NATPMP(pmp.addr()))
	m := Start(Config{Ports: ports, Discover: func(context.Context) ([]Gateway, error) { return gws, nil }})
	s := waitState(t, m, StateOK)
	if s.Method != "natpmp" || len(pmp.mapped()) != 2 || len(igd.mapped()) != 0 {
		t.Fatalf("status %+v, pmp %v igd %v", s, pmp.mapped(), igd.mapped())
	}
	pmp.mu.Lock()
	before := pmp.reqs
	pmp.mu.Unlock()
	time.Sleep(1500 * time.Millisecond)
	pmp.mu.Lock()
	after := pmp.reqs
	pmp.mu.Unlock()
	if after < before+2 {
		t.Fatalf("no renewal: %d requests then %d", before, after)
	}
	m.Close()
	if len(pmp.mapped()) != 0 {
		t.Fatalf("Close left %v", pmp.mapped())
	}
}

func TestMapperFails(t *testing.T) {
	fast(t)
	m := Start(Config{Ports: ports, Discover: func(context.Context) ([]Gateway, error) { return nil, errors.New("no gateway") }})
	defer m.Close()
	if s := waitState(t, m, StateFailed); !strings.Contains(s.Detail, "no gateway") {
		t.Fatalf("detail %q", s.Detail)
	}
	f := newFakePMP(t, "203.0.113.9")
	f.mu.Lock()
	f.silent = true
	f.mu.Unlock()
	m2 := Start(Config{Ports: ports, Discover: func(context.Context) ([]Gateway, error) { return []Gateway{NATPMP(f.addr())}, nil }})
	defer m2.Close()
	waitState(t, m2, StateFailed)
}

func TestCGNAT(t *testing.T) {
	for a, want := range map[string]bool{"100.64.0.1": true, "100.127.255.254": true, "192.168.0.1": true, "10.1.1.1": true,
		"203.0.113.9": false, "8.8.8.8": false, "100.128.0.1": false} {
		if CGNAT(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
}
