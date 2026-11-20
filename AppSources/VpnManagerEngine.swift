import Foundation
import NetworkExtension
import UserNotifications
import Corebridge
import Security

@MainActor
final class VpnManagerEngine: ObservableObject {

    @Published var snapshot: TunnelSnapshot = TunnelSnapshot()
    @Published var vpnStatus: NEVPNStatus = .disconnected
    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [SubscriptionProfile] = []
    @Published var sessions: [AppIdentitySession] = []
    @Published var settings: VpnGuardSettings = VpnGuardSettings()
    @Published var activeSessionId: UUID? = nil
    @Published var localEvents: [SecurityEvent] = []
    @Published private(set) var catalogError: String?
    @Published var lastDisconnectError: String? = nil

    let resolvedExtensionId: String = SharedConstants.resolvedTunnelBundleId()
    let appGroupAvailable: Bool = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SharedConstants.appGroupId) != nil

    var vpnStatusText: String {
        switch vpnStatus {
        case .invalid: return "无效/未配置"
        case .disconnected: return "未连接"
        case .connecting: return "正在拉起扩展..."
        case .connected: return "系统 VPN 已接管"
        case .reasserting: return "正在重连..."
        case .disconnecting: return "正在断开..."
        @unknown default: return "未知状态"
        }
    }

    var activeSession: AppIdentitySession? {
        guard let id = activeSessionId else { return nil }
        return sessions.first { $0.id == id }
    }

    var combinedEvents: [SecurityEvent] {
        (snapshot.recentEvents + localEvents).sorted { $0.timestamp > $1.timestamp }
    }

    private let storage = SharedStorage()
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTask: Task<Void, Never>?
    private var startupWatchTask: Task<Void, Never>?
    private var userRequestedStop = false
    private var pendingAutoRetrySessionId: UUID? = nil
    private var lastAppliedSnapshotRevision: UInt64 = 0
    private var lastAppliedSnapshotDate: Date = .distantPast
    private var currentControlToken: String = ""
    private var commandSequence: UInt64 = 0
    private var startAttemptId: UInt64 = 0
    private var snapshotETag: String?
    private var runningNodeTests = 0
    private var refreshingSubscriptionIds = Set<UUID>()

    private let loopbackSession: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 1.5
        cfg.timeoutIntervalForResource = 2.0
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg)
    }()

    init() {
        loadCatalog()
        self.sessions = storage.loadSessions()
        self.settings = storage.loadSettings()
        self.activeSessionId = storage.loadActiveSessionId()
        self.snapshot = storage.loadSnapshot()
        self.snapshot.status = .stopped

        requestNotificationAuth()
        loadOrCreateManager()
    }

    private func loadCatalog() {
        do {
            let catalog = try storage.loadCatalog(migrate: true)
            nodes = catalog.nodes
            subscriptions = catalog.subscriptions
            catalogError = nil
        } catch {
            if let legacy = try? storage.loadCatalog() {
                nodes = legacy.nodes
                subscriptions = legacy.subscriptions
            }
            catalogError = "无法读取或迁移节点凭据，请解锁设备并检查签名权限：\(error.localizedDescription)"
        }
    }

    private func commitCatalog(nodes nextNodes: [ProxyNode], subscriptions nextSubscriptions: [SubscriptionProfile]) throws {
        if let catalogError { throw NSError(domain: "Catalog", code: 1, userInfo: [NSLocalizedDescriptionKey: catalogError]) }
        try storage.saveCatalog(CredentialCatalog(nodes: nextNodes, subscriptions: nextSubscriptions))
        nodes = nextNodes
        subscriptions = nextSubscriptions
    }

    func resetCatalogAfterError() {
        do {
            try storage.resetCatalog()
            nodes = []
            subscriptions = []
            catalogError = nil
            recordLocalEvent(.warn, tag: "STORAGE", "已重建凭据库，请重新导入机场订阅或节点")
        } catch {
            catalogError = "重建凭据库失败：\(error.localizedDescription)"
        }
    }

    private func requestNotificationAuth() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func loadOrCreateManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let error {
                    self.recordLocalEvent(.warn, tag: "VPN", "读取系统 VPN 配置失败: \(error.localizedDescription)")
                }
                if let existing = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.resolvedExtensionId
                }) {
                    self.manager = existing
                    self.vpnStatus = existing.connection.status
                    if let proto = existing.protocolConfiguration as? NETunnelProviderProtocol,
                       let raw = proto.providerConfiguration?["payload"] as? Data,
                       let decoded = try? JSONDecoder().decode(TunnelLaunchPayload.self, from: raw),
                       !decoded.controlToken.isEmpty {
                        self.currentControlToken = decoded.controlToken
                    }
                    self.observeVpnStatus(existing)
                    if existing.connection.status == .connected {
                        Task { await self.pollLoopbackMirror() }
                    } else {
                        self.snapshot.status = .stopped
                    }
                } else {
                    let mgr = NETunnelProviderManager()
                    let proto = NETunnelProviderProtocol()
                    proto.providerBundleIdentifier = self.resolvedExtensionId
                    proto.serverAddress = "GPTGuard"
                    mgr.protocolConfiguration = proto
                    mgr.localizedDescription = "GPTGuard ChatGPT 隔离"
                    mgr.isEnabled = true
                    self.manager = mgr
                    self.observeVpnStatus(mgr)
                }
            }
        }
    }

    private func observeVpnStatus(_ mgr: NETunnelProviderManager) {
        if let old = statusObserver {
            NotificationCenter.default.removeObserver(old)
            statusObserver = nil
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: mgr.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let newStatus = mgr.connection.status
                if newStatus == self.vpnStatus { return }
                self.vpnStatus = newStatus
                self.recordLocalEvent(.info, tag: "VPN", "系统 VPN 状态变更 -> \(self.vpnStatusText)")

                switch newStatus {
                case .connected:
                    self.startupWatchTask?.cancel()
                    self.pendingAutoRetrySessionId = nil
                    self.lastDisconnectError = nil
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(nanoseconds: 350_000_000)
                        guard let self, self.vpnStatus == .connected else { return }
                        await self.pollLoopbackMirror()
                    }

                case .disconnected, .invalid:
                    self.startupWatchTask?.cancel()
                    self.snapshot.status = .stopped
                    if !self.userRequestedStop {
                        self.fetchDisconnectReason(from: mgr)
                    }
                    self.userRequestedStop = false

                default:
                    // IMPORTANT: Never call sendProviderMessage while .connecting (prevents neagent code=12 race!)
                    break
                }
            }
        }
    }

    private func fetchDisconnectReason(from mgr: NETunnelProviderManager) {
        mgr.connection.fetchLastDisconnectError { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let err {
                    let nsErr = err as NSError
                    let msg = "\(nsErr.localizedDescription) (domain=\(nsErr.domain), code=\(nsErr.code))"
                    // Auto-retry ONCE on initial iOS neagent code=12 (profile registration race right after saveToPreferences)
                    if nsErr.domain == NEVPNConnectionErrorDomain && nsErr.code == 12,
                       let retrySid = self.pendingAutoRetrySessionId {
                        self.pendingAutoRetrySessionId = nil
                        self.recordLocalEvent(.warn, tag: "VPN", "首次拉起遇到系统 code=12，0.6 秒后自动重试...")
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(nanoseconds: 600_000_000)
                            self?.startProtection(forSessionId: retrySid, allowAutoRetry: false)
                        }
                        return
                    }
                    self.lastDisconnectError = msg
                    self.recordLocalEvent(.critical, tag: "VPN", "PacketTunnel 启动/断开报错: \(msg)")
                }
            }
        }
    }

    func setForeground(_ active: Bool) {
        pollTask?.cancel()
        guard active else { return }
        if catalogError != nil { loadCatalog() }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                guard !Task.isCancelled, let self else { break }
                if self.vpnStatus == .connected {
                    await self.pollLoopbackMirror()
                }
            }
        }
    }

    private func pollLoopbackMirror() async {
        guard let url = URL(string: "http://127.0.0.1:\(SharedConstants.statusMirrorPort)/snapshot") else { return }
        let token = currentControlToken
        if !token.isEmpty {
            let envelope = LoopbackEnvelope(token: token)
            var request = URLRequest(url: url)
            request.setValue(envelope.authorization, forHTTPHeaderField: "X-CG-Token")
            request.setValue(snapshotETag, forHTTPHeaderField: "If-None-Match")
            if let (data, response) = try? await loopbackSession.data(for: request),
               let http = response as? HTTPURLResponse, token == currentControlToken, vpnStatus == .connected {
                if http.statusCode == 304 { return }
                if http.statusCode == 200, let plain = try? envelope.open(data, for: "snapshot"),
                   let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: plain) {
                    if applyIncomingSnapshot(snap) { snapshotETag = http.value(forHTTPHeaderField: "ETag") }
                    return
                }
            }
        }
        if vpnStatus == .connected, !Task.isCancelled { sendViaXpcFallback("status") }
    }

    @discardableResult
    private func applyIncomingSnapshot(_ snap: TunnelSnapshot) -> Bool {
        guard vpnStatus == .connected else { return false }
        if snap.revision > 0 {
            guard snap.revision > lastAppliedSnapshotRevision else { return false }
            lastAppliedSnapshotRevision = snap.revision
        } else {
            guard snap.updatedAt > lastAppliedSnapshotDate else { return false }
        }
        lastAppliedSnapshotDate = snap.updatedAt
        snapshot = snap
        return true
    }

    // MARK: - VPN Control

    func startProtection(forSessionId sessionId: UUID, allowAutoRetry: Bool = true) {
        guard let session = sessions.first(where: { $0.id == sessionId }),
              let node = nodes.first(where: { $0.id == session.boundNodeId }) else {
            recordLocalEvent(.warn, tag: "VPN", "该身份未绑定有效节点")
            return
        }

        userRequestedStop = false
        lastDisconnectError = nil
        pendingAutoRetrySessionId = allowAutoRetry ? sessionId : nil
        activeSessionId = session.id
        storage.saveActiveSessionId(session.id)
        if let idx = sessions.firstIndex(where: { $0.id == session.id }) {
            sessions[idx].lastUsedAt = Date()
            storage.saveSessions(sessions)
        }

        if vpnStatus == .connected {
            let livePayload = TunnelLaunchPayload(node: node, session: session, settings: settings, controlToken: currentControlToken)
            if let liveData = try? JSONEncoder().encode(livePayload) {
                persistLiveConfiguration(payloadData: liveData, server: node.server)
                sendTunnelCommand("activate_payload:" + liveData.base64EncodedString())
                recordLocalEvent(.info, tag: "IDENTITY", "正在切换官方客户端身份 -> 「\(session.name)」")
            }
            return
        }

        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            recordLocalEvent(.critical, tag: "VPN", "无法生成控制通道密钥，请重试")
            return
        }
        let freshToken = Data(random).base64EncodedString()
        snapshotETag = nil
        lastAppliedSnapshotRevision = 0
        currentControlToken = freshToken
        let payload = TunnelLaunchPayload(node: node, session: session, settings: settings, controlToken: freshToken)
        guard let payloadData = try? JSONEncoder().encode(payload) else {
            recordLocalEvent(.critical, tag: "VPN", "编码隧道配置失败")
            return
        }

        guard let mgr = manager else {
            recordLocalEvent(.warn, tag: "VPN", "正在初始化系统 VPN 配置，请稍后再点一次")
            loadOrCreateManager()
            return
        }

        startAttemptId &+= 1
        let attempt = startAttemptId

        lastAppliedSnapshotDate = .distantPast
        snapshot.status = .startingCore
        snapshot.activeSessionId = session.id
        snapshot.activeSessionName = session.name
        snapshot.activeNodeName = node.name
        snapshot.killSwitchReason = nil

        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = resolvedExtensionId
        proto.serverAddress = node.server
        proto.providerConfiguration = ["payload": payloadData]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "GPTGuard ChatGPT 隔离"
        mgr.isEnabled = true
        applyOnDemand(to: mgr)

        recordLocalEvent(.info, tag: "VPN", "准备拉起扩展 [\(resolvedExtensionId)] -> 节点 \(node.name) (AppGroup=\(appGroupAvailable ? "可用" : "降级IPC+环回直传"))")

        mgr.saveToPreferences { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self, self.startAttemptId == attempt, !self.userRequestedStop else { return }
                if let err {
                    self.snapshot.status = .stopped
                    self.lastDisconnectError = err.localizedDescription
                    self.recordLocalEvent(.critical, tag: "VPN", "保存系统 VPN 配置失败: \(err.localizedDescription)（请确认使用巨魔或带 NetworkExtension 权限的证书签名）")
                    return
                }
                mgr.loadFromPreferences { [weak self] loadErr in
                    Task { @MainActor [weak self] in
                        guard let self, self.startAttemptId == attempt, !self.userRequestedStop else { return }
                        if let loadErr {
                            self.snapshot.status = .stopped
                            self.lastDisconnectError = loadErr.localizedDescription
                            self.recordLocalEvent(.critical, tag: "VPN", "加载 VPN 配置失败: \(loadErr.localizedDescription)")
                            return
                        }
                        // Brief settle delay after save/load avoids iOS neagent first-launch code=12 race
                        try? await Task.sleep(nanoseconds: 250_000_000)
                        guard self.startAttemptId == attempt, !self.userRequestedStop else { return }
                        do {
                            try (mgr.connection as? NETunnelProviderSession)?.startTunnel(
                                options: ["payload": payloadData as NSData]
                            )
                            self.recordLocalEvent(.info, tag: "VPN", "已拉起系统隔离 VPN（初始黑洞保护，正在校验出口）")
                            self.armStartupWatchdog(mgr: mgr)
                        } catch {
                            self.snapshot.status = .stopped
                            self.lastDisconnectError = error.localizedDescription
                            self.recordLocalEvent(.critical, tag: "VPN", "启动隔离 VPN 失败: \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }

    private func persistLiveConfiguration(payloadData: Data, server: String) {
        guard let mgr = manager else { return }
        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = resolvedExtensionId
        proto.serverAddress = server
        proto.providerConfiguration = ["payload": payloadData]
        mgr.protocolConfiguration = proto
        mgr.isEnabled = true
        applyOnDemand(to: mgr)
        mgr.saveToPreferences { _ in }
    }

    /// On-Demand keeps the tunnel up after crashes / reboots so ChatGPT never silently falls back to direct.
    private func applyOnDemand(to mgr: NETunnelProviderManager) {
        if settings.onDemandReconnect {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .any
            mgr.onDemandRules = [rule]
            mgr.isOnDemandEnabled = true
        } else {
            mgr.isOnDemandEnabled = false
            mgr.onDemandRules = nil
        }
    }

    private func armStartupWatchdog(mgr: NETunnelProviderManager) {
        startupWatchTask?.cancel()
        startupWatchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 15_000_000_000)
            guard !Task.isCancelled, let self else { return }
            if self.vpnStatus != .connected {
                self.fetchDisconnectReason(from: mgr)
                let msg = "等待系统拉起 PacketTunnel 超时（当前系统状态: \(self.vpnStatusText)）。请检查证书是否包含 NetworkExtension 权限。"
                if self.lastDisconnectError == nil {
                    self.lastDisconnectError = msg
                }
                self.recordLocalEvent(.critical, tag: "VPN", msg)
            }
        }
    }

    func connectNodeShortcut(_ nodeId: UUID) {
        if let existing = sessions.first(where: { $0.boundNodeId == nodeId }) {
            startProtection(forSessionId: existing.id)
        } else if let node = nodes.first(where: { $0.id == nodeId }) {
            let created = createSession(name: String(node.name.prefix(18)), accountHint: "", boundNodeId: node.id)
            startProtection(forSessionId: created.id)
        }
    }

    func tripBlackholeKillSwitch() {
        sendTunnelCommand("kill_switch")
    }

    func reverifyAndRecover() {
        if vpnStatus == .connected {
            sendTunnelCommand("reverify")
        } else if let sid = activeSessionId ?? sessions.first?.id {
            startProtection(forSessionId: sid)
        }
    }

    func stopVpnCompletely() {
        userRequestedStop = true
        startAttemptId &+= 1
        pendingAutoRetrySessionId = nil
        startupWatchTask?.cancel()
        if let mgr = manager, mgr.isOnDemandEnabled {
            // On-Demand would immediately relaunch the tunnel; disable it before stopping.
            mgr.isOnDemandEnabled = false
            mgr.saveToPreferences { _ in
                mgr.connection.stopVPNTunnel()
            }
        } else {
            manager?.connection.stopVPNTunnel()
        }
        snapshot.status = .stopped
        snapshot.killSwitchReason = nil
        recordLocalEvent(.info, tag: "VPN", "已完全关闭系统 VPN")
    }

    private func sendReloadPayload(_ payloadData: Data) {
        let cmd = "reload_payload:" + payloadData.base64EncodedString()
        sendTunnelCommand(cmd)
    }

    private func pushCurrentPayloadToRunningTunnel() {
        guard vpnStatus == .connected,
              let sess = activeSession,
              let node = nodes.first(where: { $0.id == sess.boundNodeId }),
              let data = try? JSONEncoder().encode(TunnelLaunchPayload(node: node, session: sess, settings: settings, controlToken: currentControlToken)) else {
            return
        }
        persistLiveConfiguration(payloadData: data, server: node.server)
        sendReloadPayload(data)
    }

    private func sendTunnelCommand(_ cmd: String) {
        guard vpnStatus == .connected else { return }

        commandSequence = max(commandSequence + 1, DispatchTime.now().uptimeNanoseconds)
        let message = "\(commandSequence):\(cmd)"
        let token = currentControlToken
        let envelope = LoopbackEnvelope(token: token)
        guard !token.isEmpty, let url = URL(string: "http://127.0.0.1:\(SharedConstants.statusMirrorPort)/cmd"),
              let body = try? envelope.seal(Data(message.utf8), for: "command") else {
            sendViaXpcFallback(message)
            return
        }
        Task {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.httpBody = Data(body.utf8)
            req.setValue(envelope.authorization, forHTTPHeaderField: "X-CG-Token")
            if let (data, resp) = try? await loopbackSession.data(for: req),
               (resp as? HTTPURLResponse)?.statusCode == 200 {
                if let plain = try? envelope.open(data, for: "snapshot"),
                   let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: plain),
                   currentControlToken == token {
                    applyIncomingSnapshot(snap)
                }
                // Follow up quickly after PacketTunnel's serial queue finishes applying the command.
                try? await Task.sleep(nanoseconds: 150_000_000)
                if currentControlToken == token && vpnStatus == .connected {
                    await pollLoopbackMirror()
                }
                return
            }
            if currentControlToken == token && vpnStatus == .connected { sendViaXpcFallback(message) }
        }
    }

    private func sendViaXpcFallback(_ cmd: String) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = cmd.data(using: .utf8) else { return }
        try? session.sendProviderMessage(data) { [weak self] respData in
            guard let respData, let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: respData) else { return }
            Task { @MainActor [weak self] in
                self?.applyIncomingSnapshot(snap)
            }
        }
    }

    // MARK: - Sessions, Nodes & Subscriptions

    @discardableResult
    func createSession(name: String, accountHint: String, boundNodeId: UUID) -> AppIdentitySession {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let sess = AppIdentitySession(
            name: clean.isEmpty ? "官方身份 #\(sessions.count + 1)" : clean,
            accountHint: accountHint.trimmingCharacters(in: .whitespacesAndNewlines),
            boundNodeId: boundNodeId
        )
        sessions.append(sess)
        storage.saveSessions(sessions)
        recordLocalEvent(.success, tag: "IDENTITY", "已创建官方客户端身份「\(sess.name)」")
        return sess
    }

    func rebindSessionNode(sessionId: UUID, newNodeId: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].boundNodeId = newNodeId
        sessions[idx].lockExitIp = false
        sessions[idx].pinnedExitIp = nil
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func pinSessionExitIp(sessionId: UUID, ip: String) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = true
        sessions[idx].pinnedExitIp = ip
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func clearSessionExitIp(sessionId: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = false
        sessions[idx].pinnedExitIp = nil
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func deleteSession(_ sessionId: UUID) {
        if activeSessionId == sessionId {
            if vpnStatus == .connected {
                tripBlackholeKillSwitch()
            }
            activeSessionId = nil
            storage.saveActiveSessionId(nil)
        }
        sessions.removeAll { $0.id == sessionId }
        storage.saveSessions(sessions)
    }

    func importNodesFromText(_ rawText: String) -> ParseBatchResult {
        let res = NodeUriParser.parseInput(rawText)
        if !res.nodes.isEmpty {
            do { try commitCatalog(nodes: nodes + res.nodes, subscriptions: subscriptions) }
            catch { return ParseBatchResult(nodes: [], errors: [error.localizedDescription]) }
            recordLocalEvent(.success, tag: "NODES", "成功导入 \(res.nodes.count) 个节点")
        }
        return res
    }

    func addAndSyncSubscription(name: String, url: String, allowDirectBootstrap: Bool) async throws -> (SubscriptionProfile, Int) {
        let cleanUrl = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = SubscriptionProfile(
            name: cleanName.isEmpty ? "机场订阅" : cleanName,
            url: cleanUrl,
            allowDirectBootstrap: allowDirectBootstrap
        )
        return try await syncSub(profile, isNew: true)
    }

    func refreshSubscription(_ subId: UUID) async throws -> (SubscriptionProfile, Int) {
        guard let existing = subscriptions.first(where: { $0.id == subId }) else {
            throw NSError(domain: "Sub", code: 2, userInfo: [NSLocalizedDescriptionKey: "未找到订阅"])
        }
        guard refreshingSubscriptionIds.insert(subId).inserted else {
            throw NSError(domain: "Sub", code: 3, userInfo: [NSLocalizedDescriptionKey: "该订阅正在刷新"])
        }
        defer { refreshingSubscriptionIds.remove(subId) }
        return try await syncSub(existing, isNew: false)
    }

    private func syncSub(_ profile: SubscriptionProfile, isNew: Bool) async throws -> (SubscriptionProfile, Int) {
        let activePort = vpnStatus == .connected && snapshot.status == .protected ? snapshot.probePort : nil
        let (meta, batch) = try await SubscriptionFetcher.fetchAndParse(
            urlString: profile.url,
            activeCorePort: activePort,
            allowDirectBootstrap: profile.allowDirectBootstrap
        )
        try Task.checkCancellation()
        let subscriptionIndex = subscriptions.firstIndex(where: { $0.id == profile.id })
        guard isNew || subscriptionIndex != nil else {
            throw NSError(domain: "Sub", code: 4, userInfo: [NSLocalizedDescriptionKey: "该订阅已删除"])
        }
        let existingNodes = nodes.filter { $0.subscriptionId == profile.id }
        let tagged = SubscriptionNodeMerge.merge(batch.nodes, with: existingNodes, subscriptionId: profile.id)
        let removedNodeIds = Set(existingNodes.map(\.id)).subtracting(tagged.map(\.id))
        let affectedSessions = sessions.filter { removedNodeIds.contains($0.boundNodeId) }
        var updated = profile
        if updated.name == "机场订阅", let s = meta.suggestedName, !s.isEmpty { updated.name = s }
        updated.lastUpdated = Date()
        updated.nodeCount = tagged.count
        updated.uploadBytes = meta.uploadBytes ?? updated.uploadBytes
        updated.downloadBytes = meta.downloadBytes ?? updated.downloadBytes
        updated.totalBytes = meta.totalBytes ?? updated.totalBytes
        updated.expireTimestampSec = meta.expireTimestampSec ?? updated.expireTimestampSec

        var nextSubscriptions = subscriptions
        if let subscriptionIndex { nextSubscriptions[subscriptionIndex] = updated }
        else { nextSubscriptions.append(updated) }
        try commitCatalog(nodes: nodes.filter { $0.subscriptionId != profile.id } + tagged, subscriptions: nextSubscriptions)

        recordLocalEvent(.success, tag: "SUB", "订阅「\(updated.name)」已更新 \(tagged.count) 个节点")
        if affectedSessions.contains(where: { $0.id == activeSessionId }) { tripBlackholeKillSwitch() }
        if !affectedSessions.isEmpty {
            recordLocalEvent(.warn, tag: "SUB", "订阅更新后有 \(affectedSessions.count) 个身份的原节点已不存在，请重新绑定")
        }
        return (updated, tagged.count)
    }

    func deleteSubscription(_ subId: UUID) {
        if let activeSession, nodes.contains(where: { $0.subscriptionId == subId && $0.id == activeSession.boundNodeId }) { tripBlackholeKillSwitch() }
        do {
            try commitCatalog(nodes: nodes.filter { $0.subscriptionId != subId }, subscriptions: subscriptions.filter { $0.id != subId })
        } catch { recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription) }
    }

    func deleteNode(_ nodeId: UUID) {
        if activeSession?.boundNodeId == nodeId { tripBlackholeKillSwitch() }
        do {
            try commitCatalog(nodes: nodes.filter { $0.id != nodeId }, subscriptions: subscriptions)
        } catch { recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription) }
    }

    func testNodeIsolated(_ node: ProxyNode) async -> ExitCheckResult {
        guard runningNodeTests < 3 else { return ExitCheckResult(success: false, error: "已有 3 个测速任务，请稍后再试") }
        runningNodeTests += 1
        defer { runningNodeTests -= 1 }
        guard let port = try? LoopbackPort.allocate() else { return ExitCheckResult(success: false, error: "无法分配本地测速端口") }
        guard let cfg = try? TunnelSingBoxConfigGenerator.generateStandaloneProbe(node: node, corePort: port) else {
            return ExitCheckResult(success: false, error: "节点配置生成失败")
        }
        let resp: String = await Task.detached(priority: .userInitiated) {
            CorebridgeStartTempCore(cfg)
        }.value
        guard resp.hasPrefix("OK:") else {
            return ExitCheckResult(success: false, error: resp.replacingOccurrences(of: "ERR:", with: ""))
        }
        let handle = String(resp.dropFirst(3))

        try? await Task.sleep(nanoseconds: 250_000_000)
        let check = await ExitIpVerifier.verify(corePort: port, enrichGeo: true, timeoutSec: 8)
        await Task.detached { CorebridgeStopTempCore(handle) }.value
        if check.success, let idx = nodes.firstIndex(where: { $0.id == node.id }) {
            var measured = nodes
            measured[idx].lastLatencyMs = check.latencyMs
            measured[idx].lastExitIp = check.exitIp
            measured[idx].lastExitCountry = check.countryCode
            measured[idx].lastExitOrg = check.org ?? measured[idx].lastExitOrg
            do { try commitCatalog(nodes: measured, subscriptions: subscriptions) }
            catch { recordLocalEvent(.warn, tag: "STORAGE", error.localizedDescription) }
        }
        return check
    }

    func updateSettings(_ mutate: (inout VpnGuardSettings) -> Void) {
        var copy = settings
        mutate(&copy)
        settings = copy
        storage.saveSettings(copy)
        if vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func pinGlobalExitIp() {
        guard let ip = snapshot.exitIp else { return }
        updateSettings { $0.lockExitIp = true; $0.pinnedExitIp = ip }
    }

    func clearGlobalExitIp() {
        updateSettings { $0.lockExitIp = false; $0.pinnedExitIp = nil }
    }

    func recordLocalEvent(_ level: EventLevel, tag: String, _ message: String) {
        localEvents.insert(SecurityEvent(level: level, tag: tag, message: message), at: 0)
        if localEvents.count > 60 { localEvents = Array(localEvents.prefix(60)) }
    }

    func clearLogs() {
        localEvents = []
        snapshot.recentEvents = []
        storage.saveSnapshot(snapshot)
    }
}
