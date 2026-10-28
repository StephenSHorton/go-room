package room

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// lan_windows.go finds the interfaces whose network is on the Public
// firewall profile (café Wi-Fi), so the LAN carrier sends nothing there. It
// reads the Network List Manager as Toru's internal/lan/adapter/nlm_windows.go
// does: enumerate network connections, take each one's adapter GUID and its
// network's category, then map the GUIDs to interface indexes.

const clsidNetworkListManager = "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"

var iidINetworkConnection = ole.NewGUID("{DCB00005-570F-4A9B-8D69-199FDBA5723B}")

const nlmCategoryPublic = 0

// Vtable layouts from netlistmgr.h; both are dual interfaces, so the methods
// follow IDispatch's seven slots.
type iNetworkConnectionVtbl struct {
	ole.IDispatchVtbl
	GetNetwork            uintptr
	IsConnectedToInternet uintptr
	IsConnected           uintptr
	GetConnectivity       uintptr
	GetConnectionID       uintptr
	GetAdapterID          uintptr
	GetDomainType         uintptr
}

type iNetworkVtbl struct {
	ole.IDispatchVtbl
	GetName                    uintptr
	SetName                    uintptr
	GetDescription             uintptr
	SetDescription             uintptr
	GetNetworkID               uintptr
	GetDomainType              uintptr
	GetNetworkConnections      uintptr
	GetTimeCreatedAndConnected uintptr
	IsConnectedToInternet      uintptr
	IsConnected                uintptr
	GetConnectivity            uintptr
	GetCategory                uintptr
	SetCategory                uintptr
}

var publicCache struct {
	mu  sync.Mutex
	at  time.Time
	set map[int]bool
}

// publicInterfaces returns the indexes of interfaces on the Public profile,
// cached for 30 s (presence goes out every 30 s). If the Network List
// Manager can't be read, nothing is skipped: a home LAN that goes silent
// for a COM error would be worse than the rare café that hears a sealed,
// tag-rotating datagram.
func publicInterfaces() map[int]bool {
	publicCache.mu.Lock()
	defer publicCache.mu.Unlock()
	if publicCache.set != nil && time.Since(publicCache.at) < 30*time.Second {
		return publicCache.set
	}
	set := map[int]bool{}
	guids, err := publicAdapterGUIDs()
	if err == nil && len(guids) > 0 {
		for guid, idx := range adapterIndexes() {
			if guids[guid] {
				set[idx] = true
			}
		}
	}
	publicCache.set, publicCache.at = set, time.Now()
	return set
}

// adapterIndexes maps each adapter's GUID (upper case, with braces) to its
// IPv4 interface index.
func adapterIndexes() map[string]int {
	out := map[string]int{}
	size := uint32(16 << 10)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, aa, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return out
		}
		for a := aa; a != nil; a = a.Next {
			name := strings.ToUpper(windows.BytePtrToString(a.AdapterName))
			out[name] = int(a.IfIndex)
		}
		return out
	}
	return out
}

// publicAdapterGUIDs returns the adapter GUIDs whose network is Public.
func publicAdapterGUIDs() (map[string]bool, error) {
	out := map[string]bool{}
	err := withCOM(func() error {
		unk, err := oleutil.CreateObject(clsidNetworkListManager)
		if err != nil {
			return fmt.Errorf("create NetworkListManager: %w", err)
		}
		defer unk.Release()
		nlm, err := unk.QueryInterface(ole.IID_IDispatch)
		if err != nil {
			return err
		}
		defer nlm.Release()
		v, err := oleutil.CallMethod(nlm, "GetNetworkConnections")
		if err != nil {
			return fmt.Errorf("GetNetworkConnections: %w", err)
		}
		defer func() { _ = v.Clear() }()
		enum := v.ToIDispatch()
		if enum == nil {
			return errors.New("GetNetworkConnections: not IDispatch")
		}
		return oleutil.ForEach(enum, func(item *ole.VARIANT) error {
			defer func() { _ = item.Clear() }() // ForEach hands over a reference and never releases it
			iu := item.ToIUnknown()
			if iu == nil {
				return nil
			}
			nc, err := iu.QueryInterface(iidINetworkConnection)
			if err != nil {
				return nil
			}
			defer nc.Release()
			vt := (*iNetworkConnectionVtbl)(unsafe.Pointer(nc.RawVTable))
			// Each out-parameter's uintptr(unsafe.Pointer(&x)) sits in the
			// syscall.SyscallN argument list itself: only there does the
			// compiler keep x alive and in place for the call. Through a
			// wrapper the address is a plain integer, and a stack growth on
			// the way in moves x out from under it.
			var id ole.GUID
			r, _, _ := syscall.SyscallN(vt.GetAdapterID, uintptr(unsafe.Pointer(nc)), uintptr(unsafe.Pointer(&id)))
			if hresult(r) != nil {
				return nil
			}
			var net *ole.IDispatch
			r, _, _ = syscall.SyscallN(vt.GetNetwork, uintptr(unsafe.Pointer(nc)), uintptr(unsafe.Pointer(&net)))
			if hresult(r) != nil || net == nil {
				return nil
			}
			defer net.Release()
			nv := (*iNetworkVtbl)(unsafe.Pointer(net.RawVTable))
			var cat int32
			r, _, _ = syscall.SyscallN(nv.GetCategory, uintptr(unsafe.Pointer(net)), uintptr(unsafe.Pointer(&cat)))
			if hresult(r) != nil {
				return nil
			}
			if cat == nlmCategoryPublic {
				out[strings.ToUpper(id.String())] = true
			}
			return nil
		})
	})
	return out, err
}

// withCOM runs fn on a locked OS thread with COM initialized (MTA).
func withCOM(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		if !errors.As(err, &oe) || oe.Code() != 1 { // S_FALSE: already initialized
			return fmt.Errorf("CoInitializeEx: %w", err)
		}
	}
	defer ole.CoUninitialize()
	return fn()
}

func hresult(r uintptr) error {
	if int32(r) < 0 {
		return ole.NewError(r)
	}
	return nil
}
