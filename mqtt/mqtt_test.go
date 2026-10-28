package mqtt

import (
	"testing"

	room "github.com/StephenSHorton/go-room"
)

// No test here reaches a broker: the only address dialed is a closed port on
// 127.0.0.1, so nothing leaves the machine and nothing listens.
func TestOpenSignalOffline(t *testing.T) {
	s, err := room.SecretFromCode("go-room-test", room.NewCode())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := OpenSignal(s, "a", room.SignalOptions{}, Options{Brokers: [][]string{{"tcp://127.0.0.1:1"}, {"tcp://127.0.0.1:2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Connected() != 0 {
		t.Fatal("connected to nothing")
	}
	if err := sig.Send("", "hello", nil); err != room.ErrNotConnected {
		t.Fatalf("send offline: %v", err)
	}
	sig.Close()
	if err := sig.Send("", "hello", nil); err != room.ErrClosed {
		t.Fatalf("send after close: %v", err)
	}
	if _, err := OpenSignal(s, "a", room.SignalOptions{}, Options{Brokers: [][]string{{}}}); err == nil {
		t.Fatal("no brokers accepted")
	}
	if len(DefaultBrokers) != 2 {
		t.Fatal("default brokers")
	}
}
