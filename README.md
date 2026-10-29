# go-room

Pure-Go rooms: copies of an app find each other with no account, then talk directly over WebRTC data channels.

```go
import room "github.com/StephenSHorton/go-room" // package room
```

- **Signaling** (presence, offers and answers) is sealed with a key derived from a secret the members share, and goes over one or more **carriers**. A room is one `Signaler` that publishes each envelope on every carrier and keeps the first copy that arrives, so one carrier being down changes nothing. The carriers:
  - **the LAN**: sealed UDP datagrams to each local subnet's broadcast address, then unicast. Two devices on one network find each other with nothing else running and no internet.
  - **a hub**: a small TLS signaling server that one of your own machines runs (a home server). Devices prove their key to it, and it routes sealed bytes by topic. It comes with a TURN server and router port mapping, so devices away from home reach it.
  - **public MQTT brokers** (EMQX and HiveMQ, in package `go-room/mqtt`), as Toru uses. An app that doesn't import that package never links an MQTT client.
- **Peers** are [pion](https://github.com/pion/webrtc) PeerConnections, one per pair of members, with STUN for hole punching and an optional TURN relay. Each connection is bound to both sides' ed25519 keys by a signed-fingerprint handshake. The app gets one reliable, ordered message channel per peer and as many byte streams as it opens. The peer layer doesn't know which carriers its signaler has.
- No cgo, no helper process. It builds for Windows, macOS and Linux.

It was extracted from [Toru](https://github.com/StephenSHorton/toru)'s rooms (`internal/stream/room.go` and `ice.go`). The code alphabet, scrypt parameters, sealing and envelope JSON are Toru's, so Toru can move onto it without a wire change. Irori's device mesh is the second user.

## Pieces

| | |
|---|---|
| `NewCode`, `NormalizeCode` | Room codes like `ABCD-EFGH-JKMN-PQRS`: 16 symbols from a 31-letter alphabet with no 0/O or 1/I/L, about 79 bits. Typed in any case, with or without dashes. |
| `SecretFromCode(app, code)` | scrypt(code, salt = app, N=2^15, r=8, p=1) gives a 32-byte sealing key and a topic `app/<hex>`. Use it for anything a person types. |
| `SecretFromKey(app, ikm, info)` | HKDF-SHA256 version for high-entropy keys, for example a per-person topic derived from a secret every device holds, plus an epoch. Never feed it a typed code. |
| `Open(secret, self, opts, carriers...)` | The live room over every carrier given. It returns at once; carriers connect and reconnect in the background. `Send(to, type, body)`, with `to` set to `""` for everyone. `OnMsg` gets every envelope that isn't one of `Mesh`'s own `rtc.*` types. `OnConnect` fires on each carrier (re)connect, so you can announce yourself. `OnHeard(from, addr)` reports where an authentic envelope came from on the LAN. `Connected()` counts carriers that are up. |
| `Carrier`, `Leg` | What a carrier implements. `Join(topic, deliver, up)` gives a `Leg` with `Publish(to, payload)`, `Seen(member, addr)`, `Up()` and `Close()`. A carrier moves sealed bytes and never holds a key: sealing, filtering, de-duplication and the age check are `Open`'s. |
| `NewMemHub()` | An in-process fake hub for tests: `Carrier()`, or `Open(...)` as shorthand for `room.Open(..., h.Carrier())`. |
| `OpenLAN(LANConfig)` | The LAN carrier: one UDP socket on a fixed port (Irori: 38419) for every room. See [LAN](#lan). `NewMemLAN()` is an in-process broadcast domain for tests. |
| `NewHub(HubConfig)`, `Serve(ln)` | The hub server; see [Home server](#home-server). `Local()` carries the server's own rooms in process. `OpenGuest`, `CloseGuest` and `Drop` manage pairing windows and revokes. |
| `DialHub(HubDialConfig)` | A hub client. It dials every address it has at once, keeps the first that completes the handshake, and reconnects by itself (1 s doubling to 60 s). `Carrier()`, `Up()`, `Addr()`, `Server()`, `OpenGuest`, `CloseGuest`, `TURN(ctx)`. |
| `NewTURN(TURNConfig)` | A TURN server on `pion/turn`, with credentials minted by `Issue(user)` and `IssueGuest(until)`. |
| `SplitTCP(ln)` | One TCP port for the hub and TURN over TCP, split by each connection's first byte. |
| `portmap.Start(Config)` | Router port mapping over UPnP-IGD or NAT-PMP, renewed until `Close` removes it. |
| `mqtt.OpenSignal(secret, self, opts, mqtt.Options{})` | A room over the public brokers, one carrier per broker set. `mqtt.Carrier` puts them beside other carriers. |
| `NewRelay(cfg, peer, onChange)` | The ICE list: `DefaultSTUN`, plus TURN while short-lived credentials are good. They come from `CredentialURL` (the TURN REST scheme) or from `Fetch` (for example `HubClient.TURN`). It refreshes at 80% of the ttl and keeps working credentials through fetch failures until they expire. `Servers()` includes `DefaultSTUN`; `TURN()` is the list without it, for an app with STUN of its own. `Status()` is `none`, `pending`, `ok` or `error`. |
| `NewMesh(sig, cfg)` | Connections to other members. `Connect(peer)` offers if this side is the offerer (default: the lower id), and otherwise sends `rtc.want` so the other side offers. It is idempotent, with a backoff from 1 s up to 60 s after failed attempts. `OnPeer` fires once a peer is authenticated and accepted on both sides, `OnPeerDown` when one goes away. After a drop neither side asked for (the connection failed), Mesh reconnects by itself, about six tries over a minute; after a `Close`, a bye or a refusal it doesn't. Call `Connect` again whenever you see the peer in the room. When a newer connection to a member replaces an up one, `OnPeerDown` gets `ErrReplaced` for the old `*Peer` just before `OnPeer` for the new one, so key per-peer state on the `*Peer`. Errors to tell apart: `ErrClosed`, `ErrTooBig`, `ErrRefused`, `ErrReplaced`, `*ByeError`, `*LocalCloseError`. |
| `Peer` | `Messages()` is a `*Channel` with `Send` and `Recv` of whole messages up to `MaxMessage` (default 4 MiB). `OpenStream(ctx, label)` and `OnStream` give byte streams, each `io.ReadWriteCloser` on its own data channel. A stream is raw bytes with no message boundaries, so frame any request you send on it yourself. `OpenStream` waits while `MaxStreams` (default 4) of your streams are open; the receiving side takes up to twice that, because it frees a slot only when its handler closes the stream. `Close` unblocks a `Write` stuck on a reader that stopped reading, and `WriteContext` takes a context. `Pub()`, `Fingerprints()`, `Path()` (`direct` or `relay`), `RTT()`, `Close(reason)`. |
| `LoopbackOnly()` | A `Config.Tune` that keeps pion on 127.0.0.1, for tests. Pair it with `ICE: func() []ICEServer { return nil }`. |

Messages and stream writes go out in SCTP messages of at most 16 KiB, because pion's default cap is 64 KiB. Writers block while more than 1 MiB is queued on a channel and resume once it drains to 256 KiB. SCTP keeps channels independent, so a big stream never holds up the message channel. Data channels are detached (`SettingEngine.DetachDataChannels`), and mDNS is off.

## LAN

`OpenLAN` binds the wildcard address on its port, because broadcasts reach only a wildcard bind on Windows.
- **Everyone:** an envelope for everyone goes to the directed broadcast address of each up interface with a private IPv4 address (192.168.1.255 for 192.168.1.20/24). It never goes to 255.255.255.255, which Windows sends out of one interface only.
- **Public networks:** on Windows, interfaces whose network is on the Public firewall profile get nothing, so a laptop on café Wi-Fi sends no datagrams there. If the Network List Manager can't be read, nothing is skipped.
- **One member:** an envelope for one member is unicast to the address its last authentic envelope came from. Until one is known it is broadcast.
- IPv4 only.

Each datagram is `"GR1" || tag(8) || nonce(24) || secretbox`, at most 8 KiB. The tag is the first 8 bytes of `SHA-256("go-room/lan/1" || topic || u64(unix seconds / 300))`. A receiver finds the room by it without trying every key, and since it changes every 5 minutes, a listener can't follow one device from network to network by a fixed value. Receivers accept the previous, current and next window's tag and drop anything else unopened. Only the first copy of an envelope that arrives with an address teaches the leg (and `OnHeard`) where its sender is, so a host that resends a captured datagram from its own address can't redirect that member's unicast. They open at most `MaxRate` datagrams a second (default 200), and drop their own broadcasts coming back.

There is no mDNS. Port 5353 belongs to the OS responders, a service record names the service in clear text, and the sealed datagram does discovery and signaling at once.

## Home server

One of your own always-on machines can be the server your devices meet at. It runs a hub for signaling, a TURN server for networks that block direct paths, and port mapping so devices away from home reach both. Data still flows device to device; the hub only introduces them.

**One port number** N serves everything. `SplitTCP` sends TCP connections that start with `0x16` (TLS) to the hub and `0x00`/`0x01` (STUN) to TURN over TCP, and closes anything else. UDP N carries STUN and TURN.

**The hub wire.** TLS 1.3 over TCP, ALPN `go-room-hub/1`, then frames of `u32 length || u8 type || body`, at most 64 KiB: `hello`, `welcome`, `sub`, `unsub`, `pub`, `msg`, `guest.open`, `guest.close`, `turn.get`, `turn.creds`, `ping`, `pong` and `err`. The certificate is self-signed, has no names, is made fresh at every start, and is never pinned. Instead, both ends sign the TLS exporter (`EXPORTER-go-room-hub`, 32 bytes) with their device keys:
```
client = ed25519(device key, "go-room/hub/client/1" || 0x00 || x || len(id) || id)
server = ed25519(device key, "go-room/hub/server/1" || 0x00 || x || len(id) || id)
```
- The client signs first, and the hub checks it with `HubConfig.Authorize(id, pub)` before it says anything.
- A bad signature, an unknown key, a guest topic that isn't open, or a malformed or late `hello` closes the connection without a reply.
- The client checks the hub's `welcome` with `HubDialConfig.Expect(id, pub)`.
- `x` is unique to the TLS session, so a man in the middle can't relay either signature.

**Who may use which topic.**
- **Members** may subscribe to the topics `AllowTopic` allows and to open guest topics. By default `AllowTopic` allows the topics the server's own rooms have open through `Local()`.
- **Guests** are devices pairing with only a code. A guest gets the one topic its `hello` names, and only while a member has it open with `guest.open`: at most 10 minutes, and at most 2 per member.
- **The bridge:** `Bridge` carries open guest topics between the server's LAN and the hub, so a new device at home reaches a member away from home.
- **Closing:** closing a guest topic drops its guests and revokes their TURN credentials. `Drop(id)` closes a revoked member and its guest topics.
- **Limits** (`HubLimits`): 64 members, 8 guests, 4 handshakes in flight per IP (an IPv6 /64 counts as one) and 64 in all, with a backoff after a failed handshake, 8 topics per connection, 50 `pub` a second. A member's guest topics outlive its last connection by a short grace. The hub keeps nothing.

**TURN.** `NewTURN` runs `pion/turn` on the UDP socket and the TCP side of `SplitTCP`, with relayed sockets on the server's LAN address. Those sockets are never mapped on the router.
- **Credentials** are the TURN REST scheme: `"<expiry>:<handle>"` and `base64(HMAC-SHA1(key, username))`, where a member's handle is its user masked with a keystream from the key and the expiry, so the username names no stable id. The 32-byte key never leaves the server. They last 12 hours and are handed out only over the hub (`turn.get`).
- **Integrity first:** pion asks the auth handler before it checks MESSAGE-INTEGRITY, so a client's address is learned only from the `OnAuth` event of a verified request.
- **Revocation:** `Authorize(user)` runs on every authenticated request, allocation refreshes included, so a revoked device loses its relay at its next refresh.
- **Peers:** by default, members may relay to the server's own private subnets and to relayed addresses on the server. Guests may relay only to relayed addresses. Neither may relay to loopback, link-local, multicast or the internet.
- **Caps:** 8 allocations per user, 32 in all, 4 across every guest; a revoked guest's allocations close. TURN over TCP takes 64 connections (8 per IP) and closes one that reads nothing for 5 minutes.
- There is no `turns:`, because what TURN carries is DTLS already.

**Port mapping** (`go-room/portmap`).
- **UPnP-IGD** goes through [goupnp](https://github.com/huin/goupnp): WANIPConnection 2, then 1, then WANPPPConnection 1. Discovery keeps only an IGD at the default gateway's own address.
- **NAT-PMP** is go-room's own client, sent to the default gateway from [jackpal/gateway](https://github.com/jackpal/gateway).
- **Leases** default to 1 h and renew at half of what was granted. A router that grants only permanent leases gets those. `Close` removes the mappings; `Config.Stale` removes what an earlier run left (after a crash) if it still points at this machine. The external address is re-read every 3 minutes.
- **Conflicts:** a conflict on the external port takes another one.
- **CGNAT:** `Status` gives the router's external address and says whether it is CGNAT (100.64.0.0/10) or private space. There a mapping succeeds but reaches nobody.

**Windows Firewall.** The app's LAN socket, hub, TURN and pion's own sockets listen on real interfaces, which is the point of them. Windows asks once to allow the app on private networks, and that one program rule covers every port. If it is denied, nothing reaches the server and the LAN carrier hears nothing.

## Security model

**What the carriers see.** A hub, a broker or anyone on the LAN sees a topic, which is a hash-derived name that identifies nobody, and sealed bytes (NaCl `secretbox`, XSalsa20-Poly1305, with a fresh 24-byte nonce per envelope). They also see your IP address, the times you publish and the sizes of your messages. On the LAN, a tag that changes every 5 minutes takes the topic's place. A hub also sees which members are connected, and from where. MQTT client ids are a prefix plus random bytes, never the member id. Nobody without the room secret can read, forge or alter an envelope. A carrier can drop, delay or replay envelopes: duplicates are dropped by id, and envelopes more than `MaxAge` (default 2 minutes) old or ahead are dropped. That also means a machine whose clock is more than 2 minutes off can't signal at all.

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
  The fingerprints are read from the connected DTLS transport, not from the SDP that crossed a carrier. Each side checks the other's signature against the `devicePub` it sent, and checks that `deviceId` is the id signaling used. Then it asks your `Accept(peer, pub)`. The two sides exchange the verdicts (`{v:1, ok}`), and the peer is up only when both accepted, so the app's first message on `Messages()` is the third on the channel. `Accept` runs inside the 10 s handshake and gets no fingerprints: a pairing SAS runs after `OnPeer`, over `Messages()`, and until it matches the app should treat the peer as unconfirmed. The `auth` message also carries a random per-connection token (see below). A relayed or replayed signature is useless: it names this connection's DTLS certificates, whose private keys are fresh for every connection and never leave the two machines.

**What a room-key holder can still do.** Anyone with the room secret (a code holder during a pairing, or a device that was revoked but still has an old key while that topic stays open) can read every member's SDP, and so their candidate addresses, and see who is present. They can spoil attempts that haven't finished the handshake: a forged `rtc.answer` that wins the race, a forged `rtc.bye` with the attempt's session id, or a forged newer `rtc.offer` that supersedes a pending attempt on the answering side costs that attempt and a backoff (at most a minute). This stays open on purpose. Before the handshake, nothing in signaling is secret from a room-key holder, and Mesh holds no key for the peer that it could check a signature against. `Accept` is a decision made inside DTLS, and a pairing's `Accept` pins the first key it sees, so calling it on a signaling claim would hand a code holder the pin. Closing this would need a pre-handshake key lookup and signed signaling, and peers on older versions couldn't talk to it. The attacker gets a delay, never a connection or a message, and only while it holds a key for that topic. They can't take down a connection that is up: a newer `rtc.offer` is answered beside it and replaces it only after the new connection passes the handshake, so it needs that member's device key and your `Accept`; an offer not newer on the offerer's clock than the live one's is dropped (that also catches a carrier replaying an old offer); `rtc.want` closes an up connection only when ICE has stopped hearing the peer; and `rtc.bye` closes it only when it carries the token from that side's `auth` message, which travelled inside DTLS.

**What it doesn't authenticate.**
- **Whether a key belongs to who you think.** go-room proves "this connection is held by whoever holds the private key for `pub`". `Accept` is where you decide whether that `pub` may be `peer`: check it against a key you pinned or certified earlier.
- **A first contact.** When two sides have no keys for each other yet, as in a pairing, the code holder in the middle problem is yours to close. Someone who knows the code can sit between the two sides and run two DTLS sessions. Compare a short authentication string over both keys and `Peer.Fingerprints()` on both screens. They differ under a man in the middle.
- **Signaling metadata,** such as who is present. Presence is just envelopes, so any room member can claim to be anyone there. Only a peer that passes the handshake is authenticated.
- **Traffic analysis** by carriers, STUN servers or a TURN relay. A TURN relay sees encrypted DTLS packets and both ends' addresses.

**A hub reached from the internet.** With a port mapped, a scanner finds two things:
- a TLS 1.3 server whose certificate has no names and changes at every start, and which says nothing without a valid `hello`;
- a STUN server that answers Binding with the scanner's own address and refuses Allocate (401, realm `relay`).

It doesn't learn whose server it is, which devices exist, or any topic. A guest topic is open for at most 10 minutes and named by a hash of a pairing code. A certified device can send UDP through TURN to hosts on the server's LAN until it is revoked; that is the price of relaying to LAN devices.

## Example

```go
secret, _ := room.SecretFromCode("myapp-room-v1", code)
lan, _ := room.OpenLAN(room.LANConfig{Port: 38419})
hub := room.DialHub(room.HubDialConfig{
    Self:     self,
    Identity: &ident,
    Addrs:    func() []string { return serverAddrs() }, // its LAN and public addresses
    Expect:   func(id string, pub ed25519.PublicKey) error { return checkServer(id, pub) },
})
sig, _ := room.Open(secret, self, room.SignalOptions{
    OnConnect: func() { announce() },                          // sig.Send("", "hello", nil)
    OnMsg:     func(e room.Envelope) { mesh.Connect(e.From) }, // on "hello"
}, lan.Carrier(), hub.Carrier())
relay := room.NewRelay(room.RelayConfig{Fetch: hub.TURN}, self, nil)
relay.Start()
mesh, _ := room.NewMesh(sig, room.Config{
    Self:     self,
    Identity: room.KeyIdentity(privateKey),
    Accept:   func(peer string, pub ed25519.PublicKey) error { return checkKnown(peer, pub) },
    ICE:      relay.TURN, // the home server's STUN and TURN, no public STUN
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

The server side is `NewHub` and `Serve` on the hub half of `SplitTCP`, `NewTURN` on the TURN half and the UDP socket, the server's own rooms on `hub.Local()` beside the LAN, and `portmap.Start` for the router.

More code:
- `mqtt/example_test.go` is a broker version that compiles.
- `mesh_test.go` runs two peers in one process over `MemHub` and loopback.
- `hub_test.go` and `lan_test.go` run the same over a real hub and LAN sockets on 127.0.0.1.

## Notes

- One `Mesh` per `Signaler`. That is why a room is one `Signaler` over many carriers, not one per carrier: two signalers on one topic would make two connections to the same member. To listen on two topics at once, for example while a key rotates, open two signalers and two meshes. Whether two members that both reached the new topic also stay connected on the old one is the app's choice (`Allow`).
- `Secret.Topic` is `app + "/" + hex`. An app with an existing wire format can rewrite the prefix and keep the suffix. Toru's is `toru/v1/`.
- `Config.ICE` nil means `DefaultSTUN`; a func that returns nil means no servers.
- pion never reuses a data channel id within one connection, so a connection can open about 32,000 streams in its lifetime.

## Checks (run locally - no CI)

```sh
gofmt -l .                              # prints nothing
go vet ./...
go test ./... -count=1 -timeout 300s
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build ./...
GOOS=linux go build ./...
```

Tests run on 127.0.0.1 only:
- `MemHub` and `MemLAN` signaling;
- the LAN carrier on 127.0.0.1 sockets with 127.0.0.1 targets (no broadcast, no wildcard bind, no multicast);
- the hub and TURN on 127.0.0.1 listeners, and `LoopbackOnly` peers;
- the credential endpoint on `httptest`, and fake UPnP and NAT-PMP gateways on 127.0.0.1;
- the `mqtt` test, which dials only a closed port on 127.0.0.1.

Nothing contacts the public brokers or STUN servers or binds a LAN address, so a fresh test binary doesn't raise a Windows Firewall prompt.

## Licence

MIT. See [LICENSE](LICENSE).
