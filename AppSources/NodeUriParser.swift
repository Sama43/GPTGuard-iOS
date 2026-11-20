import Foundation

enum NodeUriParser {

    static func parseInput(_ rawInput: String) -> ParseBatchResult {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return ParseBatchResult(nodes: [], errors: ["输入内容为空"])
        }

        // 1. Raw sing-box JSON
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") {
            return parseRawSingBoxJson(trimmed)
        }

        // 2. Clash / Mihomo YAML
        if ClashYamlParser.looksLikeClashYaml(trimmed) {
            let yamlRes = ClashYamlParser.parse(trimmed)
            if !yamlRes.nodes.isEmpty { return yamlRes }
        }

        // 3. Base64-encoded subscription body
        var linesSource = trimmed
        if !trimmed.contains("://"), let decoded = decodeBase64(trimmed) {
            if ClashYamlParser.looksLikeClashYaml(decoded) {
                let yamlRes = ClashYamlParser.parse(decoded)
                if !yamlRes.nodes.isEmpty { return yamlRes }
            }
            if decoded.contains("://") {
                linesSource = decoded
            }
        }

        let lines = linesSource
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        var nodes: [ProxyNode] = []
        var errors: [String] = []
        for line in lines {
            do {
                nodes.append(try parseSingleUri(line))
            } catch {
                errors.append("\(line.prefix(36))... -> \(error.localizedDescription)")
            }
        }
        return ParseBatchResult(nodes: nodes, errors: errors)
    }

    static func parseSingleUri(_ uriString: String) throws -> ProxyNode {
        let trimmed = uriString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let schemeRange = trimmed.range(of: "://") else {
            throw err("无效的链接格式")
        }
        let scheme = trimmed[..<schemeRange.lowerBound].lowercased()
        switch scheme {
        case "vless": return try parseVless(trimmed)
        case "vmess": return try parseVmess(trimmed)
        case "trojan": return try parseTrojan(trimmed)
        case "ss": return try parseShadowsocks(trimmed)
        case "hysteria2", "hy2": return try parseHysteria2(trimmed)
        case "tuic": return try parseTuic(trimmed)
        case "socks", "socks5": return try parseSocks5(trimmed)
        case "http", "https": return try parseHttp(trimmed)
        default: throw err("不支持的协议: \(scheme)")
        }
    }

    private static func parseVless(_ raw: String) throws -> ProxyNode {
        guard let comps = URLComponents(string: raw),
              let uuid = comps.user?.removingPercentEncoding, !uuid.isEmpty,
              let host = comps.host, !host.isEmpty else {
            throw err("VLESS 链接缺少 UUID 或服务器地址")
        }
        let port = comps.port ?? 443
        let params = queryDict(comps)
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "VLESS-\(host):\(port)"
        let security = (params["security"] ?? "none").lowercased()

        var outbound: [String: Any] = [
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "packet_encoding": params["packetEncoding"] ?? "xudp"
        ]
        if let flow = params["flow"], !flow.isEmpty { outbound["flow"] = flow }
        if security == "tls" || security == "reality" {
            outbound["tls"] = buildTls(
                serverName: params["sni"] ?? params["host"] ?? host,
                insecure: isTruthy(params["allowInsecure"] ?? params["insecure"]),
                alpn: params["alpn"],
                fp: params["fp"] ?? (security == "reality" ? "chrome" : nil),
                realityPub: security == "reality" ? params["pbk"] : nil,
                realitySid: security == "reality" ? params["sid"] : nil
            )
        }
        if let tr = buildTransport(type: (params["type"] ?? "tcp").lowercased(), path: params["path"], hostHeader: params["host"] ?? params["sni"], serviceName: params["serviceName"]) {
            outbound["transport"] = tr
        }
        return ProxyNode(name: name, protocol: .vless, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseVmess(_ raw: String) throws -> ProxyNode {
        let b64 = String(raw.dropFirst("vmess://".count))
        guard let decoded = decodeBase64(b64),
              let data = decoded.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let host = (obj["add"] as? String)?.nilIfEmpty,
              let uuid = (obj["id"] as? String)?.nilIfEmpty else {
            throw err("VMess 解析失败")
        }
        let port = Int("\(obj["port"] ?? 443)") ?? 443
        let aid = Int("\(obj["aid"] ?? 0)") ?? 0
        let scy = (obj["scy"] as? String)?.nilIfEmpty ?? "auto"
        let net = ((obj["net"] as? String) ?? "tcp").lowercased()
        let tls = ((obj["tls"] as? String) ?? "").lowercased()
        let sni = (obj["sni"] as? String)?.nilIfEmpty ?? (obj["host"] as? String)?.nilIfEmpty ?? host
        let name = (obj["ps"] as? String)?.nilIfEmpty ?? "VMess-\(host):\(port)"

        var outbound: [String: Any] = [
            "type": "vmess",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "security": scy,
            "alter_id": aid
        ]
        if tls == "tls" {
            outbound["tls"] = buildTls(
                serverName: sni,
                insecure: isTruthy(obj["allowInsecure"] as? String),
                alpn: obj["alpn"] as? String,
                fp: obj["fp"] as? String,
                realityPub: nil,
                realitySid: nil
            )
        }
        if let tr = buildTransport(type: net, path: obj["path"] as? String, hostHeader: obj["host"] as? String, serviceName: obj["path"] as? String) {
            outbound["transport"] = tr
        }
        return ProxyNode(name: name, protocol: .vmess, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseTrojan(_ raw: String) throws -> ProxyNode {
        guard let comps = URLComponents(string: raw),
              let password = comps.user?.removingPercentEncoding, !password.isEmpty,
              let host = comps.host, !host.isEmpty else {
            throw err("Trojan 链接缺少密码或服务器")
        }
        let port = comps.port ?? 443
        let params = queryDict(comps)
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "Trojan-\(host):\(port)"
        let security = (params["security"] ?? "tls").lowercased()

        var outbound: [String: Any] = [
            "type": "trojan",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": password
        ]
        if security != "none" {
            outbound["tls"] = buildTls(
                serverName: params["sni"] ?? params["peer"] ?? host,
                insecure: isTruthy(params["allowInsecure"] ?? params["insecure"]),
                alpn: params["alpn"],
                fp: params["fp"],
                realityPub: security == "reality" ? params["pbk"] : nil,
                realitySid: security == "reality" ? params["sid"] : nil
            )
        }
        if let tr = buildTransport(type: (params["type"] ?? "tcp").lowercased(), path: params["path"], hostHeader: params["host"] ?? params["sni"], serviceName: params["serviceName"]) {
            outbound["transport"] = tr
        }
        return ProxyNode(name: name, protocol: .trojan, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseShadowsocks(_ raw: String) throws -> ProxyNode {
        let withoutScheme = String(raw.dropFirst("ss://".count))
        let fragSplit = withoutScheme.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        let mainPart = String(fragSplit[0]).split(separator: "?", maxSplits: 1).first.map(String.init) ?? ""
        let name = fragSplit.count > 1 ? String(fragSplit[1]).removingPercentEncoding?.nilIfEmpty : nil

        let method: String
        let password: String
        let host: String
        let port: Int

        if let atIdx = mainPart.lastIndex(of: "@") {
            let userPart = String(mainPart[..<atIdx])
            let hostPort = String(mainPart[mainPart.index(after: atIdx)...])
            let decodedUser = userPart.contains(":") ? (userPart.removingPercentEncoding ?? userPart) : (decodeBase64(userPart) ?? userPart)
            let up = decodedUser.split(separator: ":", maxSplits: 1)
            guard up.count == 2 else { throw err("SS 用户认证格式无效") }
            method = String(up[0])
            password = String(up[1])
            (host, port) = try splitHostPort(hostPort)
        } else {
            guard let decoded = decodeBase64(mainPart), let atIdx = decoded.lastIndex(of: "@") else {
                throw err("SS Base64 解码失败")
            }
            let userPart = String(decoded[..<atIdx])
            let hostPort = String(decoded[decoded.index(after: atIdx)...])
            let up = userPart.split(separator: ":", maxSplits: 1)
            guard up.count == 2 else { throw err("SS 格式无效") }
            method = String(up[0])
            password = String(up[1])
            (host, port) = try splitHostPort(hostPort)
        }

        let outbound: [String: Any] = [
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password
        ]
        return ProxyNode(name: name ?? "SS-\(host):\(port)", protocol: .shadowsocks, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseHysteria2(_ raw: String) throws -> ProxyNode {
        let normalized = raw.lowercased().hasPrefix("hy2://") ? "hysteria2://" + raw.dropFirst(6) : raw
        guard let comps = URLComponents(string: normalized),
              let host = comps.host, !host.isEmpty else {
            throw err("Hysteria2 缺少服务器")
        }
        let port = comps.port ?? 443
        let password = comps.user?.removingPercentEncoding ?? ""
        let params = queryDict(comps)
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "Hy2-\(host):\(port)"

        var outbound: [String: Any] = [
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": password,
            "tls": buildTls(
                serverName: params["sni"] ?? host,
                insecure: isTruthy(params["insecure"] ?? params["allowInsecure"]),
                alpn: params["alpn"],
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )
        ]
        if let obfs = params["obfs"], !obfs.isEmpty, obfs != "none" {
            var o: [String: Any] = ["type": obfs]
            if let p = params["obfs-password"] { o["password"] = p }
            outbound["obfs"] = o
        }
        return ProxyNode(name: name, protocol: .hysteria2, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseTuic(_ raw: String) throws -> ProxyNode {
        guard let comps = URLComponents(string: raw),
              let uuid = comps.user?.removingPercentEncoding, !uuid.isEmpty,
              let host = comps.host, !host.isEmpty else {
            throw err("TUIC 缺少参数")
        }
        let port = comps.port ?? 443
        let password = comps.password?.removingPercentEncoding ?? ""
        let params = queryDict(comps)
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "TUIC-\(host):\(port)"

        var outbound: [String: Any] = [
            "type": "tuic",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "congestion_control": params["congestion_control"] ?? "bbr",
            "udp_relay_mode": params["udp_relay_mode"] ?? "native",
            "tls": buildTls(
                serverName: params["sni"] ?? host,
                insecure: isTruthy(params["allow_insecure"] ?? params["insecure"]),
                alpn: params["alpn"] ?? "h3",
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )
        ]
        if !password.isEmpty { outbound["password"] = password }
        return ProxyNode(name: name, protocol: .tuic, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseSocks5(_ raw: String) throws -> ProxyNode {
        guard let comps = URLComponents(string: raw), let host = comps.host, !host.isEmpty else {
            throw err("SOCKS5 缺少服务器")
        }
        let port = comps.port ?? 1080
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "SOCKS5-\(host):\(port)"
        var outbound: [String: Any] = [
            "type": "socks",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "version": "5"
        ]
        if let u = comps.user?.removingPercentEncoding, !u.isEmpty { outbound["username"] = u }
        if let p = comps.password?.removingPercentEncoding, !p.isEmpty { outbound["password"] = p }
        return ProxyNode(name: name, protocol: .socks5, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseHttp(_ raw: String) throws -> ProxyNode {
        guard let comps = URLComponents(string: raw), let host = comps.host, !host.isEmpty else {
            throw err("HTTP 代理缺少服务器")
        }
        let isHttps = comps.scheme?.lowercased() == "https"
        let port = comps.port ?? (isHttps ? 443 : 8080)
        let name = comps.fragment?.removingPercentEncoding?.nilIfEmpty ?? "HTTP-\(host):\(port)"
        var outbound: [String: Any] = [
            "type": "http",
            "tag": "proxy",
            "server": host,
            "server_port": port
        ]
        if let u = comps.user?.removingPercentEncoding, !u.isEmpty { outbound["username"] = u }
        if let p = comps.password?.removingPercentEncoding, !p.isEmpty { outbound["password"] = p }
        if isHttps {
            outbound["tls"] = buildTls(serverName: host, insecure: false, alpn: nil, fp: nil, realityPub: nil, realitySid: nil)
        }
        return ProxyNode(name: name, protocol: .http, server: host, port: port, rawUri: raw, singBoxOutboundJson: toJson(outbound))
    }

    private static func parseRawSingBoxJson(_ rawJson: String) -> ParseBatchResult {
        guard let data = rawJson.data(using: .utf8),
              let elem = try? JSONSerialization.jsonObject(with: data) else {
            return ParseBatchResult(nodes: [], errors: ["JSON 解析失败"])
        }

        let objects: [[String: Any]]
        if let arr = elem as? [[String: Any]] {
            objects = arr
        } else if let dict = elem as? [String: Any], let outs = dict["outbounds"] as? [[String: Any]] {
            objects = outs.filter {
                let t = ($0["type"] as? String ?? "").lowercased()
                return !["direct", "block", "dns", "selector", "urltest"].contains(t)
            }
        } else if let dict = elem as? [String: Any], dict["type"] != nil {
            objects = [dict]
        } else {
            return ParseBatchResult(nodes: [], errors: ["未找到有效的 sing-box outbound"])
        }

        let nodes: [ProxyNode] = objects.enumerated().map { idx, obj in
            var norm = obj
            norm["tag"] = "proxy"
            let type = (obj["type"] as? String ?? "custom").lowercased()
            let server = obj["server"] as? String ?? "custom"
            let port = obj["server_port"] as? Int ?? 0
            let name = (obj["tag"] as? String)?.nilIfEmpty ?? "\(type)-\(idx + 1)"
            let proto: ProxyProtocol
            switch type {
            case "vless": proto = .vless
            case "vmess": proto = .vmess
            case "trojan": proto = .trojan
            case "shadowsocks": proto = .shadowsocks
            case "hysteria2": proto = .hysteria2
            case "tuic": proto = .tuic
            case "socks": proto = .socks5
            case "http": proto = .http
            default: proto = .rawSingBox
            }
            return ProxyNode(name: name, protocol: proto, server: server, port: port, rawUri: toJson(norm), singBoxOutboundJson: toJson(norm))
        }
        return ParseBatchResult(nodes: nodes, errors: [])
    }

    private static func buildTls(
        serverName: String?,
        insecure: Bool,
        alpn: String?,
        fp: String?,
        realityPub: String?,
        realitySid: String?
    ) -> [String: Any] {
        var tls: [String: Any] = ["enabled": true]
        if let sni = serverName, !sni.isEmpty { tls["server_name"] = sni }
        if insecure { tls["insecure"] = true }
        if let alpn = alpn, !alpn.isEmpty {
            let list = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if !list.isEmpty { tls["alpn"] = list }
        }
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

    private static func buildTransport(type: String, path: String?, hostHeader: String?, serviceName: String?) -> [String: Any]? {
        switch type {
        case "ws", "websocket":
            var tr: [String: Any] = ["type": "ws"]
            if let path = path, !path.isEmpty { tr["path"] = path }
            if let host = hostHeader, !host.isEmpty { tr["headers"] = ["Host": host] }
            return tr
        case "grpc":
            var tr: [String: Any] = ["type": "grpc"]
            if let svc = serviceName, !svc.isEmpty { tr["service_name"] = svc }
            return tr
        case "httpupgrade":
            var tr: [String: Any] = ["type": "httpupgrade"]
            if let path = path, !path.isEmpty { tr["path"] = path }
            if let host = hostHeader, !host.isEmpty { tr["host"] = host }
            return tr
        case "h2", "http":
            var tr: [String: Any] = ["type": "http"]
            if let path = path, !path.isEmpty { tr["path"] = path }
            if let host = hostHeader, !host.isEmpty { tr["host"] = [host] }
            return tr
        default:
            return nil
        }
    }

    private static func queryDict(_ comps: URLComponents) -> [String: String] {
        var dict: [String: String] = [:]
        for item in comps.queryItems ?? [] {
            if let v = item.value { dict[item.name] = v }
        }
        return dict
    }

    private static func splitHostPort(_ hp: String) throws -> (String, Int) {
        if hp.hasPrefix("["), let end = hp.firstIndex(of: "]") {
            let h = String(hp[hp.index(after: hp.startIndex)..<end])
            let rest = hp[hp.index(after: end)...]
            let p = Int(rest.replacingOccurrences(of: ":", with: "")) ?? 0
            guard p > 0 else { throw err("无效端口") }
            return (h, p)
        }
        guard let idx = hp.lastIndex(of: ":") else { throw err("无效地址端口: \(hp)") }
        let h = String(hp[..<idx])
        let p = Int(hp[hp.index(after: idx)...]) ?? 0
        guard p > 0 else { throw err("无效端口") }
        return (h, p)
    }

    private static func decodeBase64(_ input: String) -> String? {
        var s = input
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = s.count % 4
        if rem == 2 { s += "==" } else if rem == 3 { s += "=" }
        guard let data = Data(base64Encoded: s) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func isTruthy(_ v: String?) -> Bool {
        guard let v = v?.lowercased() else { return false }
        return v == "1" || v == "true"
    }

    private static func toJson(_ obj: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj),
              let s = String(data: data, encoding: .utf8) else { return "{}" }
        return s
    }

    private static func err(_ msg: String) -> NSError {
        NSError(domain: "NodeUriParser", code: 1, userInfo: [NSLocalizedDescriptionKey: msg])
    }
}

private extension String {
    var nilIfEmpty: String? {
        let t = trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }
}
