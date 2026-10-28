//go:build !windows

package room

// publicInterfaces is Windows-only: other systems have no firewall network
// profile to read, so nothing is skipped.
func publicInterfaces() map[int]bool { return nil }
