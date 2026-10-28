package mqtt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	room "github.com/StephenSHorton/go-room"
	"github.com/StephenSHorton/go-room/mqtt"
)

// Two copies of an app meet in a room named by a code one of them showed,
// connect directly, and swap a message. (Compiled, not run: it uses the
// public brokers.)
func Example() {
	code := room.NewCode() // show this on one machine, type it on the other
	secret, err := room.SecretFromCode("myapp-room-v1", code)
	if err != nil {
		log.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	self := "device-1"

	// Announce on every broker (re)connect, and connect to whoever is
	// announced. (A real app also announces every 30 s or so, and guards
	// these with a mutex or channel.)
	var sig room.Signaler
	var mesh *room.Mesh
	sig, err = mqtt.OpenSignal(secret, self, room.SignalOptions{
		OnConnect: func() {
			if sig != nil {
				_ = sig.Send("", "hello", nil)
			}
		},
		OnMsg: func(env room.Envelope) {
			if env.Type == "hello" && mesh != nil {
				mesh.Connect(env.From)
			}
		},
	}, mqtt.Options{ClientPrefix: "myapp-"})
	if err != nil {
		log.Fatal(err)
	}
	defer sig.Close()

	relay := room.NewRelay(room.RelayConfig{}, self, nil) // STUN only: "Direct only"
	relay.Start()
	defer relay.Stop()

	mesh, err = room.NewMesh(sig, room.Config{
		Self:     self,
		Identity: room.KeyIdentity(key),
		// Check the key against what you know about peer; a pairing flow
		// records it instead and confirms with a SAS over Fingerprints.
		Accept: func(peer string, pub ed25519.PublicKey) error { return nil },
		ICE:    relay.Servers,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer mesh.Close()
	mesh.OnPeer(func(p *room.Peer) {
		ctx := context.Background()
		_ = p.Messages().Send(ctx, []byte("hi from "+self))
		msg, err := p.Messages().Recv(ctx)
		fmt.Println(string(msg), err)
	})
	select {}
}
