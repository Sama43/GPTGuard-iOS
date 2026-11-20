import Foundation
import Darwin
import Network
import NetworkExtension
import UserNotifications
import Corebridge

private final class TunnelCmdBridge: NSObject, CorebridgeCommandHandlerProtocol {
    weak var owner: PacketTunnelProvider?
    init(owner: PacketTunnelProvider) {
        self.owner = owner
    }
    func onControlCommand(_ commandText: String?) {
        guard let commandText, !commandText.isEmpty else { return }
        owner?.receiveLoopbackCommand(commandText)
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    // All lifecycle callbacks, commands, and completed probes are committed on this queue.
    private let queue = DispatchQueue(label: "com.gptguard.tunnel")
    private let storage = SharedStorage()
    private var monitor: NWPathMonitor?
    private var checkTask: Task<Void, Never>?
    private var geoTask: Task<Void, Never>?
    private var generation: UInt64 = 0
    private var manuallyLocked = false
    private var offline = false
    private var lastInterface: NWInterface.InterfaceType?
    private var retryIndex = 0
    private var snapshotRevision: UInt64 = 0
    private var envelope: LoopbackEnvelope?
    private var lastCommand: UInt64 = 0
    private var lastLockDecision: UInt64 = 0
    private var cmdBridge: TunnelCmdBridge?
    private var utunFd: Int32 = -1
    private var probePort = 0
    private var proxyTag = ""
    private var currentNode: ProxyNode?
    private var currentSession: AppIdentitySession?
    private var settings = VpnGuardSettings()
    private var snapshot = TunnelSnapshot()
    private var encodedSnapshot: Data?
    private var directIps: Set<String> = []
    private var directProbeTask: Task<Void, Never>?
    private var directProbeTicket: UInt64 = 0
    private var directCheckedAt: Date = .distantPast

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async {
            self.invalidateChecks()
            let startup = self.generation
            let payload = self.resolveLaunchPayload(options: options)
            self.settings = payload?.settings ?? self.storage.loadSettings()
            let savedId = self.storage.loadActiveSessionId()
            self.currentSession = payload?.session ?? self.storage.loadSessions().first { $0.id == savedId }
            let nodeId = self.currentSession?.boundNodeId
            self.currentNode = payload?.node ?? (try? self.storage.loadCatalog())?.nodes.first { $0.id == nodeId }
            self.envelope = nil
            self.lastCommand = 0
            self.lastLockDecision = 0
            self.manuallyLocked = false
            self.offline = false
            self.lastInterface = nil
            self.retryIndex = 0
            self.snapshotRevision = 0
            self.directIps = []
            self.directCheckedAt = .distantPast
            guard let node = self.currentNode else {
                completionHandler(self.failure("未找到已绑定节点，请返回 App 重新选择"))
                return
            }
            self.snapshot = TunnelSnapshot(status: .startingCore, activeSessionId: self.currentSession?.id,
                                          activeSessionName: self.currentSession?.name, activeNodeName: node.name)
            self.setTunnelNetworkSettings(self.buildTunnelNetworkSettings()) { error in
                self.queue.async {
                    guard self.generation == startup else {
                        completionHandler(CancellationError())
                        return
                    }
                    if let error { completionHandler(error); return }
                    var fd = CorebridgeFindUtunFileDescriptor()
                    if fd < 0 { fd = (self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32) ?? -1 }
                    guard fd >= 0 else { completionHandler(self.failure("无法获取系统 utun 文件描述符")); return }
                    self.utunFd = fd
                    do {
                        self.probePort = try LoopbackPort.allocate()
                        CorebridgeConfigureTunnelMemory()
                        try self.startSealedCore()
                    } catch {
                        self.utunFd = -1
                        self.snapshot.status = .stopped
                        self.recordEvent(.critical, tag: "CORE", error.localizedDescription)
                        completionHandler(error)
                        return
                    }
                    let bridge = TunnelCmdBridge(owner: self)
                    self.cmdBridge = bridge
                    if let token = payload?.controlToken, !token.isEmpty {
                        let envelope = LoopbackEnvelope(token: token)
                        self.envelope = envelope
                        let error = CorebridgeStartStatusServer(SharedConstants.statusMirrorPort, envelope.authorization, bridge)
                        if !error.isEmpty { self.recordEvent(.warn, tag: "IPC", "本地状态服务不可用，使用系统 IPC") }
                    }
                    self.startPathMonitor()
                    self.beginVerification()
                    completionHandler(nil)
                }
            }
        }
    }

    private func failure(_ description: String) -> NSError {
        NSError(domain: "GPTGuard", code: 3, userInfo: [NSLocalizedDescriptionKey: description])
    }

    private func startSealedCore() throws {
        guard let node = currentNode else { throw failure("节点已移除，请重新绑定") }
        let directory = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("GPTGuard", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        // sing-box restores a selector's previous choice before applying its default.
        // Only the sealed tag may match a choice made by a previous core instance.
        proxyTag = "proxy-" + UUID().uuidString
        let config = try TunnelSingBoxConfigGenerator.generateTunnelConfig(node: node, probePort: probePort,
            settings: settings, cacheURL: directory.appendingPathComponent("cache.db"), proxyTag: proxyTag)
        let error = CorebridgeStartTunnelCore(config, utunFd)
        if !error.isEmpty { throw failure("sing-box 启动失败：\(error)") }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.invalidateChecks()
            self.directProbeTask?.cancel()
            self.monitor?.cancel()
            self.monitor = nil
            self.utunFd = -1
            CorebridgeStopTunnelCore()
            self.snapshot.status = .stopped
            self.snapshot.killSwitchReason = nil
            self.recordEvent(.info, tag: "TUN", "隔离 VPN 已停止")
            CorebridgeStopStatusServer()
            self.cmdBridge = nil
            completionHandler()
        }
    }

    func receiveLoopbackCommand(_ message: String) {
        queue.async {
            guard let envelope = self.envelope,
                  let plain = try? envelope.open(Data(message.utf8), for: "command") else { return }
            self.handleCommand(String(decoding: plain, as: UTF8.self))
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        queue.async {
            self.handleCommand(cmd)
            completionHandler?(self.encodedSnapshot)
        }
    }

    private func handleCommand(_ message: String) {
        if message == "status" {
            publish(persist: false)
            return
        }
        let parts = message.split(separator: ":", maxSplits: 1)
        guard utunFd >= 0, parts.count == 2, let sequence = UInt64(parts[0]) else { return }
        let cmd = String(parts[1])
        // A later passive settings refresh cannot supersede a user's manual seal.
        if cmd == "kill_switch" {
            guard sequence > lastLockDecision else { return }
            lastLockDecision = sequence
        } else {
            guard sequence > lastCommand else { return }
        }
        lastCommand = max(sequence, lastCommand)
        switch cmd {
        case "kill_switch":
            lockTraffic("已手动熔断，请手动重新校验", manual: true)
        case "reverify":
            lastLockDecision = sequence
            manuallyLocked = false
            guard seal() else { return }
            beginVerification()
        case "reload":
            guard let session = storage.loadSessions().first(where: { $0.id == storage.loadActiveSessionId() }),
                  let node = (try? storage.loadCatalog())?.nodes.first(where: { $0.id == session.boundNodeId }) else {
                lockTraffic("已绑定节点不存在，请重新绑定", manual: true)
                return
            }
            reload(node: node, session: session, settings: storage.loadSettings())
        default:
            let activate = cmd.hasPrefix("activate_payload:")
            let prefix = activate ? "activate_payload:" : "reload_payload:"
            guard cmd.hasPrefix(prefix),
                  let data = Data(base64Encoded: String(cmd.dropFirst(prefix.count))),
                  let payload = try? JSONDecoder().decode(TunnelLaunchPayload.self, from: data) else { return }
            if activate {
                lastLockDecision = sequence
                manuallyLocked = false
            }
            reload(node: payload.node, session: payload.session, settings: payload.settings)
        }
    }

    private func reload(node: ProxyNode, session: AppIdentitySession?, settings newSettings: VpnGuardSettings) {
        invalidateChecks()
        guard seal() else { return }
        let rebuild = currentNode?.singBoxOutboundJson != node.singBoxOutboundJson
            || settings.globalMode != newSettings.globalMode || settings.includeAuthHelperDomains != newSettings.includeAuthHelperDomains
        let leakToggled = settings.detectDirectLeak != newSettings.detectDirectLeak
        settings = newSettings
        if leakToggled { directIps = []; snapshot.directIp = nil; directCheckedAt = .distantPast }
        currentNode = node
        currentSession = session
        snapshot.activeSessionId = session?.id
        snapshot.activeSessionName = session?.name
        snapshot.activeNodeName = node.name
        if rebuild {
            do { try startSealedCore() }
            catch {
                CorebridgeStopTunnelCore()
                lockTraffic(error.localizedDescription, manual: true)
                return
            }
        }
        if manuallyLocked { publish(); return }
        beginVerification()
    }

    private func invalidateChecks() {
        generation &+= 1
        checkTask?.cancel()
        geoTask?.cancel()
    }

    private func seal() -> Bool {
        if !CorebridgeIsRunning() || CorebridgeSelectGuardOutbound("sealed") { return true }
        CorebridgeStopTunnelCore()
        invalidateChecks()
        manuallyLocked = true
        snapshot.status = .blackholeKillSwitch
        snapshot.killSwitchReason = "切换封锁模式失败，内核已停止，请重新校验"
        recordEvent(.critical, tag: "CORE", snapshot.killSwitchReason!)
        return false
    }

    private func lockTraffic(_ reason: String, manual: Bool, notify: Bool = true) {
        invalidateChecks()
        manuallyLocked = manual
        guard seal() else { return }
        let changed = snapshot.status != .blackholeKillSwitch || snapshot.killSwitchReason != reason
        snapshot.status = .blackholeKillSwitch
        snapshot.killSwitchReason = reason
        if changed {
            recordEvent(.warn, tag: "KILL_SWITCH", reason)
            if notify { postKillSwitchNotification(reason: reason) }
        }
    }

    private func beginVerification() {
        invalidateChecks()
        guard !manuallyLocked else { return }
        if offline { lockTraffic("网络已断开，等待恢复后校验", manual: false, notify: false); return }
        if !CorebridgeIsRunning() {
            do { try startSealedCore() }
            catch { lockTraffic(error.localizedDescription, manual: true); return }
        }
        retryIndex = 0
        snapshot.status = .verifyingExit
        snapshot.killSwitchReason = nil
        recordEvent(.info, tag: "VERIFY", "正在通过已绑定节点校验出口")
        refreshDirectIps()
        scheduleCheck(after: 0)
    }

    /// Learns the device's real public IP outside the tunnel. Network changes invalidate it.
    private func refreshDirectIps() {
        guard settings.detectDirectLeak else {
            directIps = []
            snapshot.directIp = nil
            return
        }
        directProbeTask?.cancel()
        directProbeTicket &+= 1
        let ticket = directProbeTicket
        directProbeTask = Task {
            let ips = await ExitIpVerifier.directIps(timeoutSec: 5)
            guard !Task.isCancelled else { return }
            self.queue.async {
                guard ticket == self.directProbeTicket else { return }
                self.directCheckedAt = Date()
                // Keep the last known addresses if this probe failed (e.g. transient network loss).
                guard !ips.isEmpty else { return }
                self.directIps = ips
                self.snapshot.directIp = ips.sorted { a, b in
                    (a.contains(":") ? 1 : 0, a) < (b.contains(":") ? 1 : 0, b)
                }.joined(separator: " / ")
                if let exit = self.snapshot.exitIp, ips.contains(exit),
                   self.snapshot.status == .protected, !self.manuallyLocked {
                    self.lockForDirectLeak(exitIp: exit)
                } else {
                    self.publish(persist: false)
                }
            }
        }
    }

    private func lockForDirectLeak(exitIp: String) {
        lockTraffic("检测到直连！ChatGPT 看到的出口 IP（\(exitIp)）就是本机直连 IP，节点未生效，已黑洞掐断并持续重检", manual: false)
        scheduleCheck(after: 10)
    }

    private func scheduleCheck(after delay: Int) {
        let ticket = generation
        let port = probePort
        checkTask = Task {
            do { try await Task.sleep(nanoseconds: UInt64(delay) * 1_000_000_000) }
            catch { return }
            let result = await ExitIpVerifier.verify(corePort: port, enrichGeo: false, timeoutSec: 4)
            guard !Task.isCancelled else { return }
            self.queue.async {
                guard ticket == self.generation, !self.offline, !self.manuallyLocked else { return }
                self.applyCheck(result)
            }
        }
    }

    private func applyCheck(_ result: ExitCheckResult) {
        let wasProtected = snapshot.status == .protected
        guard result.success, let ip = result.exitIp, let country = result.countryCode else {
            // Fail-closed immediately on the very first missed probe (zero grace window!).
            // Because guard selector flips instantaneously without tearing down utun, auto-retry recovers quickly.
            let errDetail = result.error.map { "：\($0)" } ?? ""
            lockTraffic("出口校验超时/断线\(errDetail)，已瞬时黑洞封锁并自动重试", manual: false)
            let delays = [2, 5, 10, 20]
            scheduleCheck(after: delays[retryIndex])
            retryIndex = min(retryIndex + 1, delays.count - 1)
            return
        }
        let ipChanged = snapshot.exitIp != ip
        snapshot.exitIp = ip
        snapshot.exitCountry = country
        snapshot.latencyMs = result.latencyMs
        if ipChanged { snapshot.exitCity = nil; snapshot.exitOrg = nil }
        if let violation = evaluatePolicyViolation(exitIp: ip, countryCode: country) {
            lockTraffic(violation, manual: true)
            return
        }
        if settings.detectDirectLeak {
            if directIps.contains(ip) {
                lockForDirectLeak(exitIp: ip)
                return
            }
            if Date().timeIntervalSince(directCheckedAt) > 120 { refreshDirectIps() }
        }
        if !wasProtected {
            guard CorebridgeSelectGuardOutbound(proxyTag) else {
                lockTraffic("无法启用已校验出口，请重新校验", manual: true)
                return
            }
            snapshot.status = .protected
            snapshot.killSwitchReason = nil
            recordEvent(.success, tag: "PROTECTED", "出口校验通过 \(country) · \(ip)")
        } else { publish(persist: false) }
        if !wasProtected || ipChanged {
            let ticket = generation
            let port = probePort
            geoTask?.cancel()
            geoTask = Task {
                guard let geo = await ExitIpVerifier.geo(corePort: port, expectedIP: ip), !Task.isCancelled else { return }
                self.queue.async {
                    guard self.generation == ticket, self.snapshot.exitIp == ip else { return }
                    self.snapshot.exitCity = geo.city
                    self.snapshot.exitOrg = geo.org
                    self.publish(persist: false)
                }
            }
        }
        retryIndex = 0
        scheduleCheck(after: max(3, min(120, settings.watchdogIntervalSec)))
    }

    private func startPathMonitor() {
        let next = NWPathMonitor()
        monitor = next
        next.pathUpdateHandler = { [weak self, weak next] path in
            guard let self, let next, self.monitor === next else { return }
            let interface = path.availableInterfaces.first { $0.type != .other && path.usesInterfaceType($0.type) }?.type
            let wasOffline = self.offline
            self.offline = path.status != .satisfied
            var switched = false
            if !self.offline, let interface {
                switched = self.lastInterface != nil && interface != self.lastInterface
                self.lastInterface = interface
            }
            guard !self.manuallyLocked else { return }
            if self.offline {
                if !wasOffline { self.lockTraffic("网络已断开，等待恢复后校验", manual: false) }
            } else if wasOffline || (switched && self.settings.killOnNetworkChange) {
                guard self.seal() else { return }
                self.beginVerification()
            }
        }
        next.start(queue: queue)
    }

    private func recordEvent(_ level: EventLevel, tag: String, _ message: String) {
        snapshot.recentEvents.insert(SecurityEvent(level: level, tag: tag, message: message), at: 0)
        snapshot.recentEvents = Array(snapshot.recentEvents.prefix(100))
        publish()
    }

    private func publish(persist: Bool = true) {
        snapshotRevision &+= 1
        snapshot.revision = snapshotRevision
        snapshot.updatedAt = Date()
        if persist { storage.saveSnapshot(snapshot) }
        var live = snapshot
        let raw = CorebridgeGetLogs()
        live.probePort = snapshot.status == .protected ? probePort : nil
        live.coreLogs = raw.isEmpty ? [] : raw.components(separatedBy: .newlines)
        encodedSnapshot = try? JSONEncoder().encode(live)
        if let data = encodedSnapshot, let envelope, let sealed = try? envelope.seal(data, for: "snapshot") {
            CorebridgeUpdateStatusJSON(sealed)
        }
    }

    private func resolveLaunchPayload(options: [String: NSObject]?) -> TunnelLaunchPayload? {
        let decoder = JSONDecoder()
        if let raw = options?["payload"] as? Data,
           let decoded = try? decoder.decode(TunnelLaunchPayload.self, from: raw) {
            return decoded
        }
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
           let raw = proto.providerConfiguration?["payload"] as? Data,
           let decoded = try? decoder.decode(TunnelLaunchPayload.self, from: raw) {
            return decoded
        }
        return nil
    }

    private func evaluatePolicyViolation(exitIp: String, countryCode: String) -> String? {
        let cc = countryCode.uppercased()
        if settings.blockedCountries.contains(cc) {
            return "高危地区黑洞熔断！出口位于禁止地区 [\(cc)] (\(exitIp))，已封锁 ChatGPT"
        }
        if !settings.allowedCountries.isEmpty && !settings.allowedCountries.contains(cc) {
            return "地区白名单黑洞熔断！出口 [\(cc)] 不在允许列表内"
        }
        if settings.lockExitIp, let pinned = settings.pinnedExitIp, !pinned.isEmpty, exitIp != pinned {
            return "全局锁 IP 漂移熔断！锁定 \(pinned) 已变为 \(exitIp) (\(cc))"
        }
        if let sess = currentSession, sess.lockExitIp, let pinned = sess.pinnedExitIp, !pinned.isEmpty, exitIp != pinned {
            return "身份「\(sess.name)」IP 漂移熔断！锁定 \(pinned) 已变为 \(exitIp) (\(cc))"
        }
        return nil
    }

    private func buildTunnelNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let net = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        net.mtu = 4064

        // Official sing-box iOS TUN addressing (172.19.0.1/30, DNS 172.19.0.2) — 100% disjoint from FakeIP 198.18.0.0/15!
        let ipv4 = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Keep system routes stable across live policy changes. Split-mode LAN traffic uses the direct outbound.
        ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0")]
        net.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        net.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["172.19.0.2"])
        dns.matchDomains = [""]
        net.dnsSettings = dns
        return net
    }

    private func postKillSwitchNotification(reason: String) {
        let content = UNMutableNotificationContent()
        content.title = "GPTGuard 黑洞熔断已生效"
        content.body = reason
        content.sound = .default
        let req = UNNotificationRequest(identifier: "cg_kill_switch", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }
}
