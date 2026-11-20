import Foundation

enum SharedConstants {
    static let appGroupId = "group.com.gptguard.ios"
    static let defaultTunnelBundleId = "com.gptguard.ios.PacketTunnel"
    static let statusMirrorPort: Int32 = 49281

    /// Dynamically discovers the embedded PacketTunnel .appex bundle ID so re-signing with a custom Bundle ID works seamlessly.
    static func resolvedTunnelBundleId() -> String {
        if let plugInsURL = Bundle.main.builtInPlugInsURL,
           let items = try? FileManager.default.contentsOfDirectory(at: plugInsURL, includingPropertiesForKeys: nil) {
            for item in items where item.pathExtension == "appex" {
                if let extBundle = Bundle(url: item),
                   let extId = extBundle.bundleIdentifier, !extId.isEmpty {
                    return extId
                }
            }
        }
        if let mainId = Bundle.main.bundleIdentifier, !mainId.isEmpty {
            return "\(mainId).PacketTunnel"
        }
        return defaultTunnelBundleId
    }
}

/// Self-contained config payload passed directly to PacketTunnel via providerConfiguration / startTunnel(options:) / XPC IPC,
/// so PacketTunnel works even when IPA re-signing strips or renames App Group entitlements.
struct TunnelLaunchPayload: Codable {
    var node: ProxyNode
    var session: AppIdentitySession?
    var settings: VpnGuardSettings
    var controlToken: String = ""
}

enum ProxyProtocol: String, Codable, CaseIterable {
    case vless = "VLESS"
    case vmess = "VMess"
    case trojan = "Trojan"
    case shadowsocks = "SS"
    case hysteria2 = "Hysteria2"
    case tuic = "TUIC"
    case socks5 = "SOCKS5"
    case http = "HTTP"
    case rawSingBox = "sing-box JSON"

    var label: String { rawValue }
}

struct ProxyNode: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var name: String
    var `protocol`: ProxyProtocol
    var server: String
    var port: Int
    var skipsTLSVerification: Bool {
        guard let outbound = (try? JSONSerialization.jsonObject(with: Data(singBoxOutboundJson.utf8))) as? [String: Any],
              let tls = outbound["tls"] as? [String: Any] else { return false }
        return tls["insecure"] as? Bool == true
    }
    var rawUri: String = ""
    var singBoxOutboundJson: String
    var subscriptionId: UUID? = nil
    var lastLatencyMs: Int? = nil
    var lastExitIp: String? = nil
    var lastExitCountry: String? = nil
    var lastExitOrg: String? = nil
    var createdAt: Date = Date()
}

struct SubscriptionProfile: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var name: String
    var url: String
    var allowDirectBootstrap: Bool = true
    var lastUpdated: Date? = nil
    var nodeCount: Int = 0
    var uploadBytes: Int64? = nil
    var downloadBytes: Int64? = nil
    var totalBytes: Int64? = nil
    var expireTimestampSec: Int64? = nil
}

struct AppIdentitySession: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var name: String
    var accountHint: String = ""
    var boundNodeId: UUID
    var lockExitIp: Bool = false
    var pinnedExitIp: String? = nil
    var createdAt: Date = Date()
    var lastUsedAt: Date? = nil
}

struct VpnGuardSettings: Codable, Equatable {
    static let defaultBlockedCountries: Set<String> = [
        "CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU"
    ]

    /// false = 仅接管 OpenAI/ChatGPT 专属域名（微信/抖音等国内App直连不受影响）；true = 全局代理与全局黑洞
    var globalMode: Bool = false
    /// 包含 Google / Apple 登录验证域名（用于官方 ChatGPT iOS 客户端 OAuth 登录）
    var includeAuthHelperDomains: Bool = true
    var blockedCountries: Set<String> = defaultBlockedCountries
    var allowedCountries: Set<String> = []
    var lockExitIp: Bool = false
    var pinnedExitIp: String? = nil
    var watchdogIntervalSec: Int = 5
    var killOnNetworkChange: Bool = true
    /// 出口 IP 与本机直连 IP 相同（节点实际未生效 / 直连泄露）时立即黑洞掐断 ChatGPT
    var detectDirectLeak: Bool = true
    /// 系统按需连接：VPN 意外断开、重启后自动拉起，避免 ChatGPT 在无保护时直连
    var onDemandReconnect: Bool = true
}

enum TunnelGuardStatus: String, Codable {
    case stopped
    case startingCore
    case verifyingExit
    case protected
    case blackholeKillSwitch
}

enum EventLevel: String, Codable {
    case info
    case success
    case warn
    case critical
}

struct SecurityEvent: Identifiable, Codable {
    var id: UUID = UUID()
    var timestamp: Date = Date()
    var level: EventLevel
    var tag: String
    var message: String
}

struct ExitCheckResult {
    let success: Bool
    var exitIp: String? = nil
    var countryCode: String? = nil
    var org: String? = nil
    var city: String? = nil
    var latencyMs: Int? = nil
    var error: String? = nil
}

struct ParseBatchResult {
    let nodes: [ProxyNode]
    let errors: [String]
}

/// Real-time status snapshot published by PacketTunnelProvider into App Group storage.
struct TunnelSnapshot: Codable {
    var revision: UInt64 = 0
    var status: TunnelGuardStatus = .stopped
    var activeSessionId: UUID? = nil
    var activeSessionName: String? = nil
    var activeNodeName: String? = nil
    var exitIp: String? = nil
    var exitCountry: String? = nil
    var exitCity: String? = nil
    var exitOrg: String? = nil
    var latencyMs: Int? = nil
    var killSwitchReason: String? = nil
    /// 扩展进程绕过隧道探测到的本机直连出口 IP（用于直连泄露比对）
    var directIp: String? = nil
    var updatedAt: Date = Date()
    var recentEvents: [SecurityEvent] = []
    var probePort: Int? = nil
    var coreLogs: [String] = []
}
