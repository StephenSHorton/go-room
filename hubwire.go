package room

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// The hub's wire: TLS 1.3 over TCP, ALPN go-room-hub/1, then frames of
//
//	u32 big-endian length || u8 type || body
//
// with the length counting the type byte and the body, at most MaxHubFrame.
// Control bodies are JSON; pub and msg bodies are u8 len || topic || sealed
// payload, the same sealed bytes every carrier moves.

// HubALPN is the hub's TLS application protocol.
const HubALPN = "go-room-hub/1"

// MaxHubFrame caps one frame, type byte included.
const MaxHubFrame = 64 << 10

// Frame types.
const (
	frameHello      byte = 1  // client, first: member {v,id,pub,sig} | guest {v,guest,topic}
	frameWelcome    byte = 2  // hub: {v,id,pub,sig}
	frameSub        byte = 3  // client: topic
	frameUnsub      byte = 4  // client: topic
	framePub        byte = 5  // client: topic, sealed payload
	frameMsg        byte = 6  // hub: topic, sealed payload
	frameGuestOpen  byte = 7  // member: {topic, ttlMs}
	frameGuestClose byte = 8  // member: {topic}
	frameTURNGet    byte = 9  // client: {id}
	frameTURNCreds  byte = 10 // hub: {id, username, credential, ttlS}
	framePing       byte = 11 // either
	framePong       byte = 12 // either
	frameErr        byte = 13 // hub: {reason}, before a close, members only
)

// Signature contexts, over ctx || 0x00 || exporter(32) || u8 len(id) || id.
const (
	hubClientContext = "go-room/hub/client/1"
	hubServerContext = "go-room/hub/server/1"
	hubExporterLabel = "EXPORTER-go-room-hub"
)

// Timing, as variables so tests can run fast.
var (
	hubHelloTimeout = 5 * time.Second  // TLS handshake plus hello
	hubPingEvery    = 15 * time.Second // client pings; the hub answers
	hubIdleTimeout  = 45 * time.Second // silence that closes a connection
	hubGuestGrace   = 45 * time.Second // a member's guest topics outlive its last connection by this
	hubWriteTimeout = 10 * time.Second
	hubDialTimeout  = 10 * time.Second
	hubRetryMin     = time.Second
	hubRetryMax     = 60 * time.Second
)

type hubHello struct {
	V     int    `json:"v"`
	ID    string `json:"id,omitempty"`
	Pub   []byte `json:"pub,omitempty"`
	Sig   []byte `json:"sig,omitempty"`
	Guest bool   `json:"guest,omitempty"`
	Topic string `json:"topic,omitempty"`
}

type hubWelcome struct {
	V   int    `json:"v"`
	ID  string `json:"id"`
	Pub []byte `json:"pub"`
	Sig []byte `json:"sig"`
}

type hubGuestBody struct {
	Topic string `json:"topic"`
	TTLMs int64  `json:"ttlMs,omitempty"`
	// Kind is GuestInvite for an invite window; "" (or a hub that doesn't
	// know it) is a pairing window, capped at MaxGuestTTL.
	Kind string `json:"kind,omitempty"`
}

// GuestInvite is hubGuestBody.Kind for an invite guest topic.
const GuestInvite = "invite"

type hubTURNBody struct {
	ID         uint64 `json:"id,omitempty"` // turn.get's, echoed in turn.creds
	Username   string `json:"username,omitempty"`
	Credential string `json:"credential,omitempty"`
	TTLS       int64  `json:"ttlS,omitempty"`
	// UDP is the hub's public address for its UDP port when the router
	// mapped it to another external port than TCP's ("ip:port").
	UDP string `json:"udp,omitempty"`
}

type hubErrBody struct {
	Reason string `json:"reason"`
}

var errHubFrame = errors.New("room: bad hub frame")

func writeFrame(w io.Writer, typ byte, body []byte) error {
	if len(body)+1 > MaxHubFrame {
		return ErrTooBig
	}
	_, err := w.Write(frameBytes(typ, body))
	return err
}

func frameBytes(typ byte, body []byte) []byte {
	b := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)+1))
	b[4] = typ
	copy(b[5:], body)
	return b
}

func readFrame(r io.Reader, limit int) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	if n < 1 || n > limit {
		return 0, nil, errHubFrame
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}

// topicBody is u8 len || topic || payload.
func topicBody(topic string, payload []byte) ([]byte, error) {
	if topic == "" || len(topic) > 255 {
		return nil, errors.New("room: hub topic must be 1-255 bytes")
	}
	b := make([]byte, 0, 1+len(topic)+len(payload))
	b = append(b, byte(len(topic)))
	b = append(b, topic...)
	return append(b, payload...), nil
}

func splitTopicBody(b []byte) (string, []byte, bool) {
	if len(b) < 1 || int(b[0]) == 0 || len(b) < 1+int(b[0]) {
		return "", nil, false
	}
	n := int(b[0])
	return string(b[1 : 1+n]), b[1+n:], true
}

func hubSigPayload(ctx string, x []byte, id string) []byte {
	b := make([]byte, 0, len(ctx)+1+len(x)+1+len(id))
	b = append(b, ctx...)
	b = append(b, 0)
	b = append(b, x...)
	b = append(b, byte(len(id)))
	return append(b, id...)
}

func hubExporter(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, errors.New("room: hub needs TLS 1.3")
	}
	if cs.NegotiatedProtocol != HubALPN {
		return nil, errors.New("room: hub ALPN not negotiated")
	}
	return cs.ExportKeyingMaterial(hubExporterLabel, nil, 32)
}

func verifyHubSig(ctx string, x []byte, id string, pub, sig []byte) bool {
	return len(id) > 0 && len(id) <= 255 && len(pub) == ed25519.PublicKeySize &&
		ed25519.Verify(ed25519.PublicKey(pub), hubSigPayload(ctx, x, id), sig)
}

func parseJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", errHubFrame, err)
	}
	return nil
}

// hubCert is a fresh self-signed ECDSA P-256 certificate with no names in
// it and a random serial. Nothing pins it: both ends sign the TLS session's
// exporter instead, so it can change at every start.
func hubCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
