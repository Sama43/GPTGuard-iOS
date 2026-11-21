import Foundation

@main
struct TunnelConfigTests {
    static func main() throws {
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let cache = directory.appendingPathComponent("cache.db")
        let node = ProxyNode(name: "Test", protocol: .socks5, server: "127.0.0.1", port: 1080,
            singBoxOutboundJson: #"{"type":"socks","server":"127.0.0.1","server_port":1080}"#)
        for global in [false, true] {
            let tag = "proxy-\(global)"
            let config = try TunnelSingBoxConfigGenerator.generateTunnelConfig(node: node, probePort: 30000,
                settings: VpnGuardSettings(globalMode: global), cacheURL: cache, proxyTag: tag)
            let root = try JSONSerialization.jsonObject(with: Data(config.utf8)) as! [String: Any]
            let experimental = root["experimental"] as! [String: [String: Any]]
            let file = experimental["cache_file"]!
            precondition(file["path"] as? String == cache.path && file["store_fakeip"] as? Bool == true)
            let outbounds = root["outbounds"] as! [[String: Any]]
            let selector = outbounds.first { $0["tag"] as? String == "guard" }!
            precondition(selector["default"] as? String == "sealed")
            precondition(selector["outbounds"] as? [String] == ["sealed", tag])
            precondition(selector["interrupt_exist_connections"] as? Bool == true)
            let dns = root["dns"] as! [String: Any]
            let dnsServers = dns["servers"] as! [[String: Any]]
            let dnsRemote = dnsServers.first { $0["tag"] as? String == "dns_remote" }!
            precondition(dnsRemote["detour"] as? String == "guard")
            let dnsProbe = dnsServers.first { $0["tag"] as? String == "dns_probe" }!
            precondition(dnsProbe["detour"] as? String == tag)
            // IPv6 disabled: no IPv6 FakeIP pool, AAAA answered empty before any other DNS rule.
            let fakeip = dnsServers.first { $0["tag"] as? String == "dns_fakeip" }!
            precondition(fakeip["inet6_range"] == nil)
            let dnsRules = dns["rules"] as! [[String: Any]]
            precondition(dnsRules.first?["query_type"] as? [String] == ["AAAA"]
                && dnsRules.first?["action"] as? String == "predefined")
            precondition(!dnsRules.dropFirst().contains { ($0["query_type"] as? [String])?.contains("AAAA") == true })
            let route = root["route"] as! [String: Any]
            precondition(route["final"] as? String == (global ? "guard" : "direct"))
            let rules = route["rules"] as! [[String: Any]]
            let probeRoute = rules.firstIndex { $0["inbound"] as? [String] == ["mixed-in"] && $0["outbound"] as? String == tag }!
            let probeResolve = rules.firstIndex { $0["inbound"] as? [String] == ["mixed-in"] && $0["action"] as? String == "resolve" }!
            precondition(probeResolve < probeRoute && rules[probeResolve]["server"] as? String == "dns_probe"
                && rules[probeResolve]["strategy"] as? String == "ipv4_only")
            let rejectV6 = rules.firstIndex { $0["ip_version"] as? Int == 6 && $0["action"] as? String == "reject" }!
            precondition(rejectV6 < probeResolve)
            let guardResolve = rules.firstIndex { $0["action"] as? String == "resolve" && $0["server"] as? String == "dns_remote" }!
            precondition(rules[guardResolve]["strategy"] as? String == "ipv4_only")
            let outbound = outbounds.first { $0["tag"] as? String == tag }!
            precondition((outbound["domain_resolver"] as? [String: Any])?["strategy"] as? String == "ipv4_only")
            if !global {
                let guardRoute = rules.firstIndex { $0["domain_suffix"] != nil && $0["outbound"] as? String == "guard" }!
                precondition(guardResolve < guardRoute && rules[guardResolve]["domain_suffix"] != nil)
                precondition(rules.contains { $0["ip_cidr"] as? [String] == ["198.18.0.0/15"] && $0["outbound"] as? String == "guard" })
            }
            try config.write(to: directory.appendingPathComponent("tunnel-\(global).json"), atomically: true, encoding: .utf8)
        }

        // Speed-test probe must also force the node to egress over IPv4.
        let probe = try TunnelSingBoxConfigGenerator.generateStandaloneProbe(node: node, corePort: 30001)
        let probeRoot = try JSONSerialization.jsonObject(with: Data(probe.utf8)) as! [String: Any]
        let probeRules = (probeRoot["route"] as! [String: Any])["rules"] as! [[String: Any]]
        precondition(probeRules.first?["action"] as? String == "resolve"
            && probeRules.first?["strategy"] as? String == "ipv4_only")

        // Domain-passthrough nodes block DNS / IP literals: no resolve rules anywhere,
        // but the phone-side IPv6 block stays in place.
        var passthroughNode = node
        passthroughNode.domainPassthrough = true
        for global in [false, true] {
            let tag = "proxy-pt-\(global)"
            let config = try TunnelSingBoxConfigGenerator.generateTunnelConfig(node: passthroughNode, probePort: 30000,
                settings: VpnGuardSettings(globalMode: global), cacheURL: cache, proxyTag: tag)
            let root = try JSONSerialization.jsonObject(with: Data(config.utf8)) as! [String: Any]
            let rules = (root["route"] as! [String: Any])["rules"] as! [[String: Any]]
            precondition(!rules.contains { $0["action"] as? String == "resolve" }, "passthrough must not resolve locally")
            precondition(rules.contains { $0["ip_version"] as? Int == 6 && $0["action"] as? String == "reject" })
            precondition(rules.contains { $0["inbound"] as? [String] == ["mixed-in"] && $0["outbound"] as? String == tag })
            let dnsRules = (root["dns"] as! [String: Any])["rules"] as! [[String: Any]]
            precondition(dnsRules.first?["query_type"] as? [String] == ["AAAA"]
                && dnsRules.first?["action"] as? String == "predefined")
            let route = root["route"] as! [String: Any]
            precondition(route["final"] as? String == (global ? "guard" : "direct"))
            if !global {
                precondition(rules.contains { $0["domain_suffix"] != nil && $0["outbound"] as? String == "guard" })
            }
        }
        let passthroughProbe = try TunnelSingBoxConfigGenerator.generateStandaloneProbe(node: passthroughNode, corePort: 30002)
        let passthroughProbeRoot = try JSONSerialization.jsonObject(with: Data(passthroughProbe.utf8)) as! [String: Any]
        let passthroughProbeRules = (passthroughProbeRoot["route"] as! [String: Any])["rules"] as! [[String: Any]]
        precondition(passthroughProbeRules.count == 1 && passthroughProbeRules[0]["outbound"] as? String == "proxy")
    }
}
