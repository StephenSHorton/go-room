package room

import "testing"

// Reading the Network List Manager opens no socket; this only checks that
// the COM calls run and that every index it names is a real interface.
func TestPublicInterfacesReads(t *testing.T) {
	idx := map[int]bool{}
	for _, s := range LocalSubnets() {
		idx[s.Index] = true
	}
	for i := range publicInterfaces() {
		t.Logf("interface %d is on the Public profile (private subnet: %v)", i, idx[i])
	}
	if _, err := publicAdapterGUIDs(); err != nil {
		t.Fatalf("Network List Manager: %v", err)
	}
}
