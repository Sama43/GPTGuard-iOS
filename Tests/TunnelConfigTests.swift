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
            let route = root["route"] as! [String: Any]
            precondition(route["final"] as? String == (global ? "guard" : "direct"))
            let rules = route["rules"] as! [[String: Any]]
            precondition(rules.contains { $0["inbound"] as? [String] == ["mixed-in"] && $0["outbound"] as? String == tag })
            if !global {
                precondition(rules.contains { $0["domain_suffix"] != nil && $0["outbound"] as? String == "guard" })
                precondition(rules.contains { $0["ip_cidr"] != nil && $0["outbound"] as? String == "guard" })
            }
            try config.write(to: directory.appendingPathComponent("tunnel-\(global).json"), atomically: true, encoding: .utf8)
        }
    }
}
