import Foundation

/// Generates sing-box 1.14.4 TUN + FakeIP configs for iOS NEPacketTunnelProvider.
///
/// Addressing (strictly disjoint so FakeIP NEVER collides with TUN or DNS!):
/// - TUN IPv4: 172.19.0.1/30 (DNS: 172.19.0.2)
/// - TUN IPv6: fdfe:dcba:9876::1/126
/// - FakeIP pool: 198.18.0.0/15 & fc00::/18
enum TunnelSingBoxConfigGenerator {

    static let openAIDomainSuffixes: [String] = [
        // OpenAI / ChatGPT first-party
        "openai.com",
        "chatgpt.com",
        "chat.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "sora.com",
        "openaiapi-site.azureedge.net",
        "openaicom.imgix.net",
        // Voice mode (WebRTC) & third-party services used by the ChatGPT iOS client / web
        "livekit.cloud",
        "browser-intake-datadoghq.com",
        "cloudflare.com",
        "challenges.cloudflare.com",
        "cloudflareinsights.com",
        "arkoselabs.com",
        "hcaptcha.com",
        "statsig.com",
        "statsigapi.net",
        "featuregates.org",
        "intercom.io",
        "intercomcdn.com",
        "sentry.io",
        "datadoghq.com",
        "segment.io",
        "segment.com",
        "launchdarkly.com",
        "stripe.com",
        "stripe.network",
        "revenuecat.com",
        "stytch.com",
        "auth0.com",
        "workos.com"
    ]

    static let authHelperDomainSuffixes: [String] = [
        "accounts.google.com",
        "oauth2.googleapis.com",
        "apis.google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "google.com",
        "appleid.apple.com"
    ]

    /// Generates a non-TUN probe-only config for isolated single-node speed testing in main app.
    static func generateStandaloneProbe(node: ProxyNode, corePort: Int) throws -> String {
        var proxyOutbound = try decodeOutbound(node)
        proxyOutbound["tag"] = "proxy"
        if proxyOutbound["domain_resolver"] == nil {
            proxyOutbound["domain_resolver"] = "dns_bootstrap"
        }

        let root: [String: Any] = [
            "log": ["level": "warn", "timestamp": false],
            "dns": [
                "servers": [
                    ["tag": "dns_remote", "type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy"],
                    ["tag": "dns_bootstrap", "type": "udp", "server": "223.5.5.5", "server_port": 53]
                ],
                "final": "dns_remote",
                "strategy": "ipv4_only"
            ],
            "inbounds": [
                ["type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": corePort]
            ],
            "outbounds": [proxyOutbound],
            "route": [
                "rules": [
                    ["inbound": ["mixed-in"], "outbound": "proxy"]
                ],
                "final": "proxy",
                "default_domain_resolver": "dns_bootstrap"
            ]
        ]
        return try encodeJson(root)
    }

    /// Generates the iOS PacketTunnel sing-box 1.14.4 config (either Blackhole Kill-Switch or Protected mode).
    static func generateTunnelConfig(
        node: ProxyNode,
        probePort: Int,
        settings: VpnGuardSettings,
        cacheURL: URL,
        proxyTag: String
    ) throws -> String {
        var proxyOutbound = try decodeOutbound(node)
        proxyOutbound["tag"] = proxyTag
        if proxyOutbound["domain_resolver"] == nil {
            proxyOutbound["domain_resolver"] = "dns_local"
        }

        let targetDomains = settings.includeAuthHelperDomains
            ? (openAIDomainSuffixes + authHelperDomainSuffixes)
            : openAIDomainSuffixes

        // DNS servers: FakeIP for protected domains so zero local ISP DNS queries leak!
        let dnsServers: [[String: Any]] = [
            [
                "tag": "dns_remote",
                "type": "https",
                "server": "1.1.1.1",
                "server_port": 443,
                "path": "/dns-query",
                "detour": "guard"
            ],
            [
                "tag": "dns_local",
                "type": "udp",
                "server": "223.5.5.5",
                "server_port": 53
            ],
            [
                "tag": "dns_fakeip",
                "type": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            ]
        ]

        var dnsRules: [[String: Any]] = []
        if settings.globalMode {
            // Global mode: A/AAAA -> FakeIP, HTTPS/SVCB -> Remote DoH over proxy
            dnsRules.append(["query_type": ["A", "AAAA"], "server": "dns_fakeip"])
        } else {
            // Split mode: OpenAI/ChatGPT A/AAAA -> FakeIP, HTTPS/SVCB -> Remote DoH over proxy; Chinese apps -> fast local DNS
            dnsRules.append([
                "domain_suffix": targetDomains,
                "query_type": ["A", "AAAA"],
                "server": "dns_fakeip"
            ])
            dnsRules.append([
                "domain_suffix": targetDomains,
                "server": "dns_remote"
            ])
        }

        var routeRules: [[String: Any]] = [
            ["action": "sniff"],
            ["protocol": "dns", "action": "hijack-dns"],
            // Local probe inbound ALWAYS routes strictly via proxy for Exit IP Watchdog
            ["inbound": ["mixed-in"], "outbound": proxyTag]
        ]

        let routeFinal: String
        if settings.globalMode {
            // Reject UDP 443 QUIC globally so TLS falls back cleanly to TCP
            routeRules.append(["network": "udp", "port": [443], "action": "reject"])
            routeFinal = "guard"
        } else {
            routeRules.append(["network": "udp", "port": [443], "domain_suffix": targetDomains, "action": "reject"])
            routeRules.append(["domain_suffix": targetDomains, "outbound": "guard"])
            routeRules.append(["ip_cidr": ["198.18.0.0/15", "fc00::/18"], "outbound": "guard"])
            routeFinal = "direct"
        }

        let root: [String: Any] = [
            "experimental": ["cache_file": ["enabled": true, "path": cacheURL.path, "store_fakeip": true]],
            "log": ["level": "info", "timestamp": false],
            "dns": [
                "servers": dnsServers,
                "rules": dnsRules,
                "final": settings.globalMode ? "dns_remote" : "dns_local",
                "strategy": "ipv4_only"
            ],
            "inbounds": [
                [
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "utun0",
                    "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                    "mtu": 4064,
                    "auto_route": false,
                    "stack": "gvisor"
                ],
                [
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": probePort
                ]
            ],
            "outbounds": [
                proxyOutbound,
                ["type": "block", "tag": "sealed"],
                ["type": "selector", "tag": "guard", "outbounds": ["sealed", proxyTag],
                 "default": "sealed", "interrupt_exist_connections": true],
                ["type": "direct", "tag": "direct"]
            ],
            "route": [
                "rules": routeRules,
                "final": routeFinal,
                "default_domain_resolver": "dns_local"
            ]
        ]

        return try encodeJson(root)
    }

    private static func decodeOutbound(_ node: ProxyNode) throws -> [String: Any] {
        guard let data = node.singBoxOutboundJson.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "TunnelConfig", code: 1, userInfo: [NSLocalizedDescriptionKey: "节点 outbound JSON 无效"])
        }
        return obj
    }

    private static func encodeJson(_ root: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: root)
        return String(data: data, encoding: .utf8) ?? "{}"
    }
}
