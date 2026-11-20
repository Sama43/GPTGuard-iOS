import Foundation
import Yams

/// Parses Clash / Mihomo YAML subscription configs ("proxies:") into sing-box 1.14.4 ProxyNodes.
enum ClashYamlParser {

    static func looksLikeClashYaml(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") { return false }
        return trimmed.contains("\nproxies:") ||
            trimmed.hasPrefix("proxies:") ||
            (trimmed.contains("type:") && trimmed.contains("server:") && trimmed.contains("port:"))
    }

    static func parse(_ yamlText: String) -> ParseBatchResult {
        var nodes: [ProxyNode] = []
        var errors: [String] = []

        let loaded: Any?
        do {
            loaded = try Yams.load(yaml: yamlText)
        } catch {
            return ParseBatchResult(nodes: [], errors: ["Clash YAML 解析失败: \(error.localizedDescription)"])
        }

        let proxyList: [Any]
        if let dict = loaded as? [String: Any], let arr = dict["proxies"] as? [Any] {
            proxyList = arr
        } else if let arr = loaded as? [Any] {
            proxyList = arr
        } else {
            return ParseBatchResult(nodes: [], errors: ["YAML 中未找到 proxies 列表"])
        }

        for item in proxyList {
            guard let m = item as? [String: Any] else { continue }
            let name = str(m, "name") ?? "Unnamed"
            guard let type = str(m, "type")?.lowercased(),
                  let server = str(m, "server"), !server.isEmpty,
                  let port = intVal(m, "port"), (1...65535).contains(port) else {
                continue
            }

            do {
                if let node = try convertEntry(name: name, type: type, server: server, port: port, m: m) {
                    nodes.append(node)
                }
            } catch {
                errors.append("\(name) (\(type)): \(error.localizedDescription)")
            }
        }

        return ParseBatchResult(nodes: nodes, errors: errors)
    }

    private static func convertEntry(
        name: String,
        type: String,
        server: String,
        port: Int,
        m: [String: Any]
    ) throws -> ProxyNode? {
        var outbound: [String: Any] = [
            "tag": "proxy",
            "server": server,
            "server_port": port
        ]
        let proto: ProxyProtocol

        switch type {
        case "vless":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 1, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .vless
            outbound["type"] = "vless"
            outbound["uuid"] = uuid
            if let flow = str(m, "flow"), !flow.isEmpty { outbound["flow"] = flow }
            outbound["packet_encoding"] = str(m, "packet-encoding") ?? "xudp"

            let reality = m["reality-opts"] as? [String: Any]
            if boolVal(m, "tls") || reality != nil {
                outbound["tls"] = buildTls(
                    server: server,
                    sni: str(m, "servername") ?? str(m, "sni"),
                    insecure: boolVal(m, "skip-cert-verify"),
                    alpn: strList(m, "alpn"),
                    fp: str(m, "client-fingerprint") ?? (reality != nil ? "chrome" : nil),
                    realityPub: reality.flatMap { str($0, "public-key") },
                    realitySid: reality.flatMap { str($0, "short-id") }
                )
            }
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "vmess":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 2, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .vmess
            outbound["type"] = "vmess"
            outbound["uuid"] = uuid
            outbound["security"] = str(m, "cipher") ?? "auto"
            outbound["alter_id"] = intVal(m, "alterId") ?? 0
            if boolVal(m, "tls") {
                outbound["tls"] = buildTls(
                    server: server,
                    sni: str(m, "servername") ?? str(m, "sni"),
                    insecure: boolVal(m, "skip-cert-verify"),
                    alpn: strList(m, "alpn"),
                    fp: str(m, "client-fingerprint"),
                    realityPub: nil,
                    realitySid: nil
                )
            }
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "trojan":
            guard let password = str(m, "password"), !password.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 3, userInfo: [NSLocalizedDescriptionKey: "缺少 password"])
            }
            proto = .trojan
            outbound["type"] = "trojan"
            outbound["password"] = password
            let reality = m["reality-opts"] as? [String: Any]
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername"),
                insecure: boolVal(m, "skip-cert-verify"),
                alpn: strList(m, "alpn"),
                fp: str(m, "client-fingerprint"),
                realityPub: reality.flatMap { str($0, "public-key") },
                realitySid: reality.flatMap { str($0, "short-id") }
            )
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "ss":
            guard let cipher = str(m, "cipher"), let password = str(m, "password") else {
                throw NSError(domain: "ClashYaml", code: 4, userInfo: [NSLocalizedDescriptionKey: "缺少 cipher/password"])
            }
            proto = .shadowsocks
            outbound["type"] = "shadowsocks"
            outbound["method"] = cipher
            outbound["password"] = password

        case "hysteria2":
            proto = .hysteria2
            outbound["type"] = "hysteria2"
            outbound["password"] = str(m, "password") ?? str(m, "auth") ?? ""
            if let obfs = str(m, "obfs"), !obfs.isEmpty, obfs != "none" {
                var o: [String: Any] = ["type": obfs]
                if let p = str(m, "obfs-password") { o["password"] = p }
                outbound["obfs"] = o
            }
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername"),
                insecure: boolVal(m, "skip-cert-verify"),
                alpn: strList(m, "alpn"),
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )

        case "tuic":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 5, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .tuic
            outbound["type"] = "tuic"
            outbound["uuid"] = uuid
            if let pw = str(m, "password"), !pw.isEmpty { outbound["password"] = pw }
            outbound["congestion_control"] = str(m, "congestion-controller") ?? "bbr"
            outbound["udp_relay_mode"] = str(m, "udp-relay-mode") ?? "native"
            let alpn = strList(m, "alpn")
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername"),
                insecure: boolVal(m, "skip-cert-verify"),
                alpn: alpn.isEmpty ? ["h3"] : alpn,
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )

        case "anytls":
            guard let password = str(m, "password"), !password.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 6, userInfo: [NSLocalizedDescriptionKey: "缺少 password"])
            }
            proto = .anytls
            outbound["type"] = "anytls"
            outbound["password"] = password
            if let v = intVal(m, "idle-session-check-interval"), v > 0 { outbound["idle_session_check_interval"] = "\(v)s" }
            if let v = intVal(m, "idle-session-timeout"), v > 0 { outbound["idle_session_timeout"] = "\(v)s" }
            if let v = intVal(m, "min-idle-session"), v >= 0 { outbound["min_idle_session"] = v }
            let reality = m["reality-opts"] as? [String: Any]
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername"),
                insecure: boolVal(m, "skip-cert-verify"),
                alpn: strList(m, "alpn"),
                fp: str(m, "client-fingerprint"),
                realityPub: reality.flatMap { str($0, "public-key") },
                realitySid: reality.flatMap { str($0, "short-id") }
            )

        case "socks5":
            proto = .socks5
            outbound["type"] = "socks"
            outbound["version"] = "5"
            if let u = str(m, "username"), !u.isEmpty { outbound["username"] = u }
            if let p = str(m, "password"), !p.isEmpty { outbound["password"] = p }

        case "http":
            proto = .http
            outbound["type"] = "http"
            if let u = str(m, "username"), !u.isEmpty { outbound["username"] = u }
            if let p = str(m, "password"), !p.isEmpty { outbound["password"] = p }
            if boolVal(m, "tls") {
                outbound["tls"] = buildTls(server: server, sni: str(m, "sni"), insecure: boolVal(m, "skip-cert-verify"), alpn: [], fp: nil, realityPub: nil, realitySid: nil)
            }

        default:
            return nil
        }

        let jsonData = try JSONSerialization.data(withJSONObject: outbound)
        let jsonStr = String(data: jsonData, encoding: .utf8) ?? "{}"
        return ProxyNode(name: name, protocol: proto, server: server, port: port, singBoxOutboundJson: jsonStr)
    }

    private static func buildTls(
        server: String,
        sni: String?,
        insecure: Bool,
        alpn: [String],
        fp: String?,
        realityPub: String?,
        realitySid: String?
    ) -> [String: Any] {
        var tls: [String: Any] = [
            "enabled": true,
            "server_name": (sni?.isEmpty == false) ? sni! : server
        ]
        if insecure { tls["insecure"] = true }
        if !alpn.isEmpty { tls["alpn"] = alpn }
        if let fp = fp, !fp.isEmpty {
            tls["utls"] = ["enabled": true, "fingerprint": fp]
        }
        if let pub = realityPub, !pub.isEmpty {
            var r: [String: Any] = ["enabled": true, "public_key": pub]
            if let sid = realitySid, !sid.isEmpty { r["short_id"] = sid }
            tls["reality"] = r
        }
        return tls
    }

    private static func buildTransport(_ m: [String: Any]) -> [String: Any]? {
        guard let net = str(m, "network")?.lowercased() else { return nil }
        switch net {
        case "ws":
            let ws = m["ws-opts"] as? [String: Any]
            let path = ws.flatMap { str($0, "path") } ?? str(m, "ws-path")
            let headers = (ws?["headers"] as? [String: Any]) ?? (m["ws-headers"] as? [String: Any])
            let host = headers.flatMap { str($0, "Host") ?? str($0, "host") }
            var tr: [String: Any] = ["type": "ws"]
            if let path = path, !path.isEmpty { tr["path"] = path }
            if let host = host, !host.isEmpty { tr["headers"] = ["Host": host] }
            return tr
        case "grpc":
            let grpc = m["grpc-opts"] as? [String: Any]
            let svc = grpc.flatMap { str($0, "grpc-service-name") } ?? str(m, "grpc-service-name")
            var tr: [String: Any] = ["type": "grpc"]
            if let svc = svc, !svc.isEmpty { tr["service_name"] = svc }
            return tr
        case "h2":
            let h2 = m["h2-opts"] as? [String: Any]
            var tr: [String: Any] = ["type": "http"]
            if let path = h2.flatMap({ str($0, "path") }), !path.isEmpty { tr["path"] = path }
            if let hosts = h2.map({ strList($0, "host") }), !hosts.isEmpty { tr["host"] = hosts }
            return tr
        case "httpupgrade":
            let ws = m["ws-opts"] as? [String: Any]
            var tr: [String: Any] = ["type": "httpupgrade"]
            if let path = ws.flatMap({ str($0, "path") }), !path.isEmpty { tr["path"] = path }
            let headers = ws?["headers"] as? [String: Any]
            if let host = headers.flatMap({ str($0, "Host") ?? str($0, "host") }), !host.isEmpty { tr["host"] = host }
            return tr
        default:
            return nil
        }
    }

    private static func str(_ m: [String: Any], _ key: String) -> String? {
        guard let v = m[key] else { return nil }
        let s = "\(v)".trimmingCharacters(in: .whitespacesAndNewlines)
        return s.isEmpty ? nil : s
    }

    private static func intVal(_ m: [String: Any], _ key: String) -> Int? {
        if let i = m[key] as? Int { return i }
        if let s = m[key] as? String { return Int(s.trimmingCharacters(in: .whitespacesAndNewlines)) }
        return nil
    }

    private static func boolVal(_ m: [String: Any], _ key: String) -> Bool {
        if let b = m[key] as? Bool { return b }
        if let i = m[key] as? Int { return i != 0 }
        if let s = m[key] as? String {
            return s.lowercased() == "true" || s == "1"
        }
        return false
    }

    private static func strList(_ m: [String: Any], _ key: String) -> [String] {
        if let arr = m[key] as? [Any] {
            return arr.map { "\($0)".trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        if let s = m[key] as? String {
            return s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        return []
    }
}
