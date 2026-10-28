# go-room

Pure-Go rooms: copies of an app find each other with no account and no server of their own, then talk directly over WebRTC data channels.

```go
import room "github.com/StephenSHorton/go-room" // package room
```

- **Signaling** goes over free public MQTT brokers (EMQX and HiveMQ by default; TLS first, WebSockets-over-TLS second). Every envelope is sealed with a key derived from a secret the members share, published through every broker and de-duplicated on arrival, so one broker being down changes nothing.
- **Peers** are [pion](https://github.com/pion/webrtc) PeerConnections, one per pair of members, with STUN for hole punching and an optional TURN relay. Each connection is bound to both sides' ed25519 keys by a signed-fingerprint handshake. The app gets one reliable, ordered message channel per peer and as many byte streams as it opens.
- No cgo, no helper process. It builds for Windows, macOS and Linux.

It was extracted from [Toru](https://github.com/StephenSHorton/toru)'s rooms (`internal/stream/room.go` and `ice.go`). The code alphabet, scrypt parameters, sealing and envelope JSON are Toru's, so Toru can move onto it without a wire change. Irori's device mesh is the second user.

## Pieces

| | |
|---|---|
| `NewCode`, `NormalizeCode` | Room codes like `ABCD-EFGH-JKMN-PQRS`: 16 symbols from a 31-letter alphabet with no 0/O or 1/I/L, about 79 bits. Typed in any case, with or without dashes. |
| `SecretFromCode(app, code)` | scrypt(code, salt = app, N=2^15, r=8, p=1) gives a 32-byte sealing key and a topic `app/<hex>`. Use it for anything a person types. |
| `SecretFromKey(app, ikm, info)` | HKDF-SHA256 version for high-entropy keys, for example a per-person topic derived from a secret every device holds, plus an epoch. Never feed it a typed code. |
| `OpenSignal(secret, self, opts)` | The live room over the public brokers. It returns at once and connects and reconnects in the background. `Send(to, type, body)`, with `to` set to `""` for everyone. `OnMsg` gets every envelope that isn't one of `Mesh`'s own `rtc.*` types. `OnConnect` fires on each broker (re)connect, so you can announce yourself. |
| `NewMemHub().Open(...)` | The same Signaler over an in-process fake broker, for tests. It uses the same sealing, filtering, de-duplication and age-check code. |
| `NewRelay(cfg, peer, onChange)` | The ICE list: `DefaultSTUN`, plus TURN while short-lived credentials from `CredentialURL` (the TURN REST scheme) are good. It refreshes at 80% of the ttl and keeps working credentials through fetch failures until they expire. `Status()` is `none`, `pending`, `ok` or `error`. |
| `NewMesh(sig, cfg)` | Connections to other members. `Connect(peer)` offers if this side is the offerer (default: the lower id), and otherwise sends `rtc.want` so the other side offers. It is idempotent, with a backoff from 1 s up to 60 s after failed attempts. `OnPeer` fires once a peer is authenticated and accepted on both sides, `OnPeerDown` when one goes away. |
| `Peer` | `Messages()` is a `*Channel` with `Send` and `Recv` of whole messages up to `MaxMessage` (default 4 MiB). `OpenStream(ctx, label)` and `OnStream` give byte streams, each `io.ReadWriteCloser` on its own data channel, at most `MaxStreams` (default 4) per direction. `Pub()`, `Fingerprints()`, `Path()` (`direct` or `relay`), `RTT()`, `Close(reason)`. |
| `LoopbackOnly()` | A `Config.Tune` that keeps pion on 127.0.0.1, for tests. Pair it with `ICE: func() []ICEServer { return nil }`. |

Messages and stream writes go out in SCTP messages of at most 16 KiB, because pion's default cap is 64 KiB. Writers block while more than 1 MiB is queued on a channel and resume once it drains to 256 KiB. SCTP keeps channels independent, so a big stream never holds up the message channel. Data channels are detached (`SettingEngine.DetachDataChannels`), and mDNS is off.

## Security model

**What the brokers see.** They see a topic, which is a hash-derived name that identifies nobody, and sealed bytes (NaCl `secretbox`, XSalsa20-Poly1305, with a fresh 24-byte nonce per envelope). They also see your IP address, the times you publish and the sizes of your messages. MQTT client ids are a prefix plus random bytes, never the member id. Nobody without the room secret can read, forge or alter an envelope. A broker can drop, delay or replay envelopes: duplicates are dropped by id, and envelopes more than `MaxAge` (default 2 minutes) old or ahead are dropped. That also means a machine whose clock is more than 2 minutes off can't signal at all.

**Codes.** A room code is the secret. Anyone who has it can join that room, read its signaling and send envelopes into it. Treat it like a one-use password. About 79 bits, behind scrypt, makes guessing one from a captured topic or message impractical. It does not stop someone who saw the code.

**What go-room authenticates.**
- **Envelopes:** membership of the room, meaning the sender holds the room key. `Envelope.From` is whatever a member claims. It is not proof of who sent it.
- **Peers:** every connection starts with an `auth` message in each direction on the message channel, before anything else:
  ```
  auth { v:1, deviceId, devicePub, sig }
  sig = ed25519(identity key, "go-room/auth/1" || 0x00 || role ('O' offerer | 'A' answerer)
                || sha256(offerer's DTLS cert) || sha256(answerer's DTLS cert)
                || sha256(topic) || len(deviceId) || deviceId)
  ```
  The fingerprints are read from the connected DTLS transport, not from the SDP that crossed the broker. Each side checks the other's signature against the `devicePub` it sent, and checks that `deviceId` is the id signaling used. Then it asks your `Accept(peer, pub)`. The two sides exchange the verdicts, and the peer is up only when both accepted. A relayed or replayed signature is useless: it names this connection's DTLS certificates, whose private keys are fresh for every connection and never leave the two machines.

**What it doesn't authenticate.**
- **Whether a key belongs to who you think.** go-room proves "this connection is held by whoever holds the private key for `pub`". `Accept` is where you decide whether that `pub` may be `peer`: check it against a key you pinned or certified earlier.
- **A first contact.** When two sides have no keys for each other yet, as in a pairing, the code holder in the middle problem is yours to close. Someone who knows the code can sit between the two sides and run two DTLS sessions. Compare a short authentication string over both keys and `Peer.Fingerprints()` on both screens. They differ under a man in the middle.
- **Signaling metadata,** such as who is present. Presence is just envelopes, so any room member can claim to be anyone there. Only a peer that passes the handshake is authenticated.
- **Traffic analysis** by brokers, STUN servers or a TURN relay. A TURN relay sees encrypted DTLS packets and both ends' addresses.

## Example

```go
secret, _ := room.SecretFromCode("myapp-room-v1", code)
sig, _ := room.OpenSignal(secret, self, room.SignalOptions{
    ClientPrefix: "myapp-",
    OnConnect:    func() { announce() },                          // sig.Send("", "hello", nil)
    OnMsg:        func(e room.Envelope) { mesh.Connect(e.From) }, // on "hello"
})
relay := room.NewRelay(room.RelayConfig{CredentialURL: credURL}, self, nil)
relay.Start()
mesh, _ := room.NewMesh(sig, room.Config{
    Self:     self,
    Identity: room.KeyIdentity(privateKey),
    Accept:   func(peer string, pub ed25519.PublicKey) error { return checkKnown(peer, pub) },
    ICE:      relay.Servers,
})
mesh.OnPeer(func(p *room.Peer) {
    go func() {
        for {
            msg, err := p.Messages().Recv(ctx)
            if err != nil {
                return // p went down; OnPeerDown says why
            }
            handle(p.ID(), msg)
        }
    }()
    p.OnStream(func(label string, s *room.Stream) { serve(label, s) })
})
```

See `example_test.go` for a version that compiles, and `mesh_test.go` for two peers in one process over `MemHub` and loopback.

## Notes

- One `Mesh` per `Signaler`. To listen on two topics at once, for example while a key rotates, open two signalers and two meshes.
- `Secret.Topic` is `app + "/" + hex`. An app with an existing wire format can rewrite the prefix and keep the suffix. Toru's is `toru/v1/`.
- pion never reuses a data channel id within one connection, so a connection can open about 32,000 streams in its lifetime.

## Checks (run locally - no CI)

```sh
gofmt -l .                              # prints nothing
go vet ./...
go test ./... -count=1 -timeout 300s
GOOS=darwin GOARCH=arm64 go build ./...
GOOS=linux go build ./...
```

Tests run on 127.0.0.1 only: `MemHub` signaling, `LoopbackOnly` peers, and the credential endpoint on `httptest`. They never contact the public brokers or STUN servers, and they never bind a LAN address, so a fresh test binary doesn't raise a Windows Firewall prompt.

## Licence

MIT. See [LICENSE](LICENSE).
