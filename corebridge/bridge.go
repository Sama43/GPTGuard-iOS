package corebridge

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/unix"
)

func ConfigureTunnelMemory() {
	// Keep Go runtime safely inside iOS NEPacketTunnelProvider's 50 MB RAM limit
	debug.SetGCPercent(20)
	debug.SetMemoryLimit(26 * 1024 * 1024)
}

// CommandHandler receives authenticated local control commands (kill_switch / reverify / reload_payload)
// from the containing app over loopback HTTP when Apple XPC sendProviderMessage is unavailable.
type CommandHandler interface {
	OnControlCommand(commandText string)
}

var (
	mu           sync.Mutex
	activeBox    *box.Box
	tempBoxes    = make(map[string]*box.Box)
	tempCounter  int64
	logMu        sync.Mutex
	logLines     []string
	statusMu     sync.RWMutex
	statusJSON   string
	statusETag   string
	statusRevision uint64
	statusServer *http.Server
	statusLn     net.Listener
)

func appendLog(msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().Format("15:04:05")
	logLines = append(logLines, fmt.Sprintf("%s %s", ts, msg))
	if len(logLines) > 200 {
		logLines = logLines[len(logLines)-200:]
	}
}

type bridgeLogWriter struct{}

func (w *bridgeLogWriter) DisableColors() bool { return true }
func (w *bridgeLogWriter) WriteMessage(level boxlog.Level, message string) {
	appendLog(message)
}

// StartStatusServer starts a loopback HTTP server (127.0.0.1:<port>):
// - GET /snapshot: read-only mirror of PacketTunnel's latest TunnelSnapshot JSON
// - POST /cmd: authenticated control endpoint (requires X-CG-Token == controlToken)
func StartStatusServer(port int32, controlToken string, handler CommandHandler) string {
	statusMu.Lock()
	defer statusMu.Unlock()

	if statusServer != nil {
		_ = statusServer.Close()
		statusServer = nil
	}
	if statusLn != nil {
		_ = statusLn.Close()
		statusLn = nil
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		appendLog("status server listen err: " + err.Error())
		return err.Error()
	}

	tokenBytes := []byte(controlToken)
	statusJSON = ""
	statusETag = ""
	authorized := func(r *http.Request) bool {
		return len(tokenBytes) >= 16 && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CG-Token")), tokenBytes) == 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		statusMu.RLock()
		body := statusJSON
		etag := statusETag
		statusMu.RUnlock()
		w.Header().Set("ETag", etag)
		if etag != "" && r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if body == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(body))
	})

	mux.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authorized(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cmd := string(raw)
		if handler != nil && cmd != "" {
			handler.OnControlCommand(cmd)
		}
		statusMu.RLock()
		body := statusJSON
		statusMu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	statusLn = ln
	statusServer = srv
	go func() {
		_ = srv.Serve(ln)
	}()
	appendLog(fmt.Sprintf("status+control mirror ready on 127.0.0.1:%d", port))
	return ""
}

func StopStatusServer() {
	statusMu.Lock()
	defer statusMu.Unlock()
	if statusServer != nil {
		_ = statusServer.Close()
		statusServer = nil
	}
	if statusLn != nil {
		_ = statusLn.Close()
		statusLn = nil
	}
}

func UpdateStatusJSON(payload string) {
	statusMu.Lock()
	statusRevision++
	statusETag = fmt.Sprintf("\"%d\"", statusRevision)
	statusJSON = payload
	statusMu.Unlock()
}

// FindUtunFileDescriptor scans open fds for iOS NEPacketTunnelProvider's com.apple.net.utun_control socket.
func FindUtunFileDescriptor() int32 {
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	for fd := 0; fd < 1024; fd++ {
		addr, err := unix.Getpeername(fd)
		if err != nil {
			continue
		}
		addrCTL, ok := addr.(*unix.SockaddrCtl)
		if !ok {
			continue
		}
		if ctlInfo.Id == 0 {
			if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
				continue
			}
		}
		if addrCTL.ID == ctlInfo.Id {
			return int32(fd)
		}
	}
	return -1
}

type iosTunPlatform struct {
	tunFd     int32
	myTunAddr []netip.Addr
}

var _ adapter.PlatformInterface = (*iosTunPlatform)(nil)

func (p *iosTunPlatform) Initialize(networkManager adapter.NetworkManager) error { return nil }
func (p *iosTunPlatform) UsePlatformAutoDetectInterfaceControl() bool           { return false }
func (p *iosTunPlatform) AutoDetectInterfaceControl(fd int) error               { return nil }
func (p *iosTunPlatform) UsePlatformInterface() bool                            { return p.tunFd >= 0 }

func (p *iosTunPlatform) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	if p.tunFd < 0 {
		return nil, fmt.Errorf("invalid iOS utun fd: %d", p.tunFd)
	}
	// SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2 on Darwin/iOS
	ifName, err := unix.GetsockoptString(int(p.tunFd), 2, 2)
	if err != nil {
		return nil, fmt.Errorf("query utun name: %w", err)
	}
	options.Name = strings.TrimRight(ifName, "\x00")
	if options.InterfaceMonitor != nil {
		options.InterfaceMonitor.RegisterMyInterface(options.Name)
	}
	dupFd, err := unix.Dup(int(p.tunFd))
	if err != nil {
		return nil, fmt.Errorf("dup utun fd: %w", err)
	}
	options.FileDescriptor = dupFd
	appendLog(fmt.Sprintf("utun opened: name=%s fd=%d->dup=%d mtu=%d", options.Name, p.tunFd, dupFd, options.MTU))

	addrs := make([]netip.Addr, 0, len(options.Inet4Address)+len(options.Inet6Address))
	for _, pref := range options.Inet4Address {
		addrs = append(addrs, pref.Addr())
	}
	for _, pref := range options.Inet6Address {
		addrs = append(addrs, pref.Addr())
	}
	p.myTunAddr = addrs
	return tun.New(*options)
}

func (p *iosTunPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error { return nil }
func (p *iosTunPlatform) UsePlatformDefaultInterfaceMonitor() bool                       { return false }
func (p *iosTunPlatform) CreateDefaultInterfaceMonitor(l logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}
func (p *iosTunPlatform) UsePlatformNetworkInterfaces() bool                     { return false }
func (p *iosTunPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (p *iosTunPlatform) UnderNetworkExtension() bool                            { return p.tunFd >= 0 }
func (p *iosTunPlatform) NetworkExtensionIncludeAllNetworks() bool               { return false }
func (p *iosTunPlatform) ClearDNSCache()                                         {}
func (p *iosTunPlatform) RequestPermissionForWIFIState() error                   { return nil }
func (p *iosTunPlatform) ReadWIFIState(ctx context.Context) adapter.WIFIState    { return adapter.WIFIState{} }
func (p *iosTunPlatform) UsePlatformConnectionOwnerFinder() bool                 { return false }
func (p *iosTunPlatform) FindConnectionOwner(req *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}
func (p *iosTunPlatform) UsePlatformWIFIMonitor() bool                             { return false }
func (p *iosTunPlatform) UsePlatformNotification() bool                            { return false }
func (p *iosTunPlatform) SendNotification(n *adapter.Notification) error           { return nil }
func (p *iosTunPlatform) CancelNotification(id string, typeID int32) error         { return nil }
func (p *iosTunPlatform) MyInterfaceAddress() []netip.Addr                         { return p.myTunAddr }
func (p *iosTunPlatform) UsePlatformNeighborResolver() bool                        { return false }
func (p *iosTunPlatform) StartNeighborMonitor(l adapter.NeighborUpdateListener) error { return nil }
func (p *iosTunPlatform) CloseNeighborMonitor(l adapter.NeighborUpdateListener) error { return nil }
func (p *iosTunPlatform) UsePlatformShell() bool                                   { return false }
func (p *iosTunPlatform) CheckPlatformShell() error                                { return os.ErrInvalid }
func (p *iosTunPlatform) OpenShellSession(user *adapter.PlatformUser, cmd string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (p *iosTunPlatform) LookupUser(username string) (*adapter.PlatformUser, error) { return nil, os.ErrInvalid }
func (p *iosTunPlatform) LookupSFTPServer() (string, error)                         { return "", os.ErrInvalid }
func (p *iosTunPlatform) ReadSystemSSHHostKey() ([]byte, error)                     { return nil, os.ErrInvalid }
func (p *iosTunPlatform) TailscaleHostname() string                                 { return "" }
func (p *iosTunPlatform) UsePlatformBridge() bool                                   { return false }
func (p *iosTunPlatform) CreateBridge(opts adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

func startInstance(configJSON string, tunFd int32, captureLogs bool) (*box.Box, error) {
	ctx := include.Context(context.Background())
	if tunFd >= 0 {
		service.MustRegister[adapter.PlatformInterface](ctx, &iosTunPlatform{tunFd: tunFd})
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configJSON))
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	boxOpts := box.Options{
		Context: ctx,
		Options: options,
	}
	if captureLogs {
		boxOpts.PlatformLogWriter = &bridgeLogWriter{}
	}
	instance, err := box.New(boxOpts)
	if err != nil {
		return nil, fmt.Errorf("create sing-box: %w", err)
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start sing-box: %w", err)
	}
	return instance, nil
}

// StartTunnelCore starts sing-box bound to iOS utun fd (pass -1 for non-TUN mode). Returns "" on success or error string.
func StartTunnelCore(configJSON string, tunFd int32) string {
	mu.Lock()
	defer mu.Unlock()

	if activeBox != nil {
		appendLog("closing previous sing-box instance")
		_ = activeBox.Close()
		activeBox = nil
		debug.FreeOSMemory()
	}

	instance, err := startInstance(configJSON, tunFd, true)
	if err != nil {
		appendLog("ERROR: " + err.Error())
		return err.Error()
	}
	activeBox = instance
	appendLog(fmt.Sprintf("sing-box 1.14.4 started OK (tunFd=%d)", tunFd))
	return ""
}

// SelectGuardOutbound switches protected connections while the TUN and FakeIP mapping stay live.
func SelectGuardOutbound(tag string) bool {
	mu.Lock()
	defer mu.Unlock()
	if activeBox == nil {
		return false
	}
	outbound, ok := activeBox.Outbound().Outbound("guard")
	if !ok {
		return false
	}
	selector, ok := outbound.(interface{ SelectOutbound(string) bool })
	return ok && selector.SelectOutbound(tag)
}

func StopTunnelCore() {
	mu.Lock()
	defer mu.Unlock()
	if activeBox != nil {
		_ = activeBox.Close()
		activeBox = nil
		debug.FreeOSMemory()
		appendLog("sing-box stopped")
	}
}

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return activeBox != nil
}

// StartTempCore starts an isolated non-TUN sing-box instance for node testing. Returns "OK:<id>" or "ERR:<msg>".
func StartTempCore(configJSON string) string {
	instance, err := startInstance(configJSON, -1, false)
	if err != nil {
		return "ERR:" + err.Error()
	}
	mu.Lock()
	defer mu.Unlock()
	tempCounter++
	id := fmt.Sprintf("tmp_%d", tempCounter)
	tempBoxes[id] = instance
	return "OK:" + id
}

func StopTempCore(handleID string) {
	mu.Lock()
	inst, ok := tempBoxes[handleID]
	if ok {
		delete(tempBoxes, handleID)
	}
	mu.Unlock()
	if ok && inst != nil {
		_ = inst.Close()
	}
}

func GetLogs() string {
	logMu.Lock()
	defer logMu.Unlock()
	return strings.Join(logLines, "\n")
}

func ClearLogs() {
	logMu.Lock()
	defer logMu.Unlock()
	logLines = nil
}
