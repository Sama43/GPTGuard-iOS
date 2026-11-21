import Foundation
import Network

/// Strictly proxied Exit IP & Country Verifier using iOS 17+ URLSessionConfiguration.proxyConfigurations.
enum ExitIpVerifier {

    static func makeStrictlyProxiedConfiguration(corePort: Int, timeoutSec: TimeInterval) -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSec
        config.timeoutIntervalForResource = timeoutSec
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData

        if let port = NWEndpoint.Port(rawValue: UInt16(corePort)) {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: port)
            let proxy = ProxyConfiguration(httpCONNECTProxy: endpoint)
            config.proxyConfigurations = [proxy]
        }
        return config
    }

    static func makeStrictlyProxiedSession(corePort: Int, timeoutSec: TimeInterval) -> URLSession {
        URLSession(configuration: makeStrictlyProxiedConfiguration(corePort: corePort, timeoutSec: timeoutSec))
    }

    static func verify(corePort: Int, enrichGeo: Bool = true, timeoutSec: TimeInterval = 8) async -> ExitCheckResult {
        guard (1...65535).contains(corePort) else {
            return ExitCheckResult(success: false, error: "代理内核端口无效")
        }

        let verified = await withTaskGroup(of: ExitCheckResult.self) { group in
            group.addTask { await checkExit(corePort: corePort, timeoutSec: timeoutSec) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSec * 1_000_000_000))
                return ExitCheckResult(success: false, error: "出口校验超时")
            }
            let first = await group.next() ?? ExitCheckResult(success: false, error: "出口校验已取消")
            group.cancelAll()
            return first
        }
        guard verified.success, enrichGeo, !Task.isCancelled, let ip = verified.exitIp else { return verified }
        let details = await geo(corePort: corePort, expectedIP: ip)
        var enriched = verified
        enriched.city = details?.city
        enriched.org = details?.org
        return enriched
    }

    private static func checkExit(corePort: Int, timeoutSec: TimeInterval) async -> ExitCheckResult {
        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: timeoutSec)
        defer { session.invalidateAndCancel() }

        let start = ProcessInfo.processInfo.systemUptime
        let deadline = start + timeoutSec

        // Primary fast check: Cloudflare trace (returns ip= and loc=)
        var exitIp: String?
        var country: String?
        var primaryErr: String?

        if let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace") {
            do {
                var req = URLRequest(url: url)
                req.timeoutInterval = timeoutSec / 2
                req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await session.data(for: req)
                if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let text = String(data: data, encoding: .utf8) {
                    var map: [String: String] = [:]
                    for line in text.components(separatedBy: .newlines) {
                        let parts = line.split(separator: "=", maxSplits: 1)
                        if parts.count == 2 {
                            map[String(parts[0])] = String(parts[1]).trimmingCharacters(in: .whitespaces)
                        }
                    }
                    exitIp = map["ip"]
                    country = map["loc"]?.uppercased()
                } else {
                    primaryErr = "HTTP 响应异常"
                }
            } catch {
                primaryErr = error.localizedDescription
            }
        }

        // Fallback: api.country.is
        if exitIp == nil || country == nil, let url = URL(string: "https://api.country.is/") {
            do {
                let remaining = deadline - ProcessInfo.processInfo.systemUptime
                guard remaining > 0, !Task.isCancelled else { throw URLError(.timedOut) }
                let (data, resp) = try await session.data(for: URLRequest(url: url, timeoutInterval: remaining))
                if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    exitIp = obj["ip"] as? String
                    country = (obj["country"] as? String)?.uppercased()
                }
            } catch {
                primaryErr = primaryErr ?? error.localizedDescription
            }
        }

        let latencyMs = max(1, Int((ProcessInfo.processInfo.systemUptime - start) * 1000))

        guard ProcessInfo.processInfo.systemUptime <= deadline, let ip = exitIp,
              IPv4Address(ip) != nil || IPv6Address(ip) != nil, let cc = country,
              cc.utf8.count == 2, cc.utf8.allSatisfy({ (65...90).contains($0) }) else {
            return ExitCheckResult(success: false, error: "代理出口探测失败: \(primaryErr ?? "无响应")")
        }

        return ExitCheckResult(
            success: true,
            exitIp: canonicalIp(ip),
            countryCode: cc,
            latencyMs: latencyMs
        )
    }
    /// Probes the device's real (direct, non-proxied) public IPs over IPv4 and IPv6.
    /// Must be called from the PacketTunnel process: the provider's own sockets bypass its tunnel,
    /// so this sees exactly the address ChatGPT would see if traffic leaked outside the proxy.
    static func directIps(timeoutSec: TimeInterval = 5) async -> Set<String> {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSec
        config.timeoutIntervalForResource = timeoutSec
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        let endpoints = [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://[2606:4700:4700::1111]/cdn-cgi/trace"
        ]
        return await withTaskGroup(of: String?.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    guard let url = URL(string: endpoint),
                          let (data, response) = try? await session.data(from: url),
                          (response as? HTTPURLResponse)?.statusCode == 200,
                          let text = String(data: data, encoding: .utf8) else { return nil }
                    for line in text.components(separatedBy: .newlines) where line.hasPrefix("ip=") {
                        let ip = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                        if IPv4Address(ip) != nil || IPv6Address(ip) != nil { return canonicalIp(ip) }
                    }
                    return nil
                }
            }
            var found = Set<String>()
            for await ip in group {
                if let ip { found.insert(ip) }
            }
            return found
        }
    }

    /// Learns a domain-passthrough node's exit per IP family. Uses domains that resolve to only an
    /// A (or only an AAAA) record, so the node itself picks the family without any IP literal.
    static func familyExits(corePort: Int, timeoutSec: TimeInterval = 3) async -> Set<String> {
        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: timeoutSec)
        defer { session.invalidateAndCancel() }
        let families: [(endpoints: [String], ipv6: Bool)] = [
            (["https://api-ipv4.ip.sb/ip", "https://ipv4.icanhazip.com/"], false),
            (["https://api-ipv6.ip.sb/ip", "https://ipv6.icanhazip.com/"], true)
        ]
        return await withTaskGroup(of: String?.self) { group in
            for family in families {
                group.addTask {
                    for endpoint in family.endpoints {
                        guard !Task.isCancelled, let url = URL(string: endpoint) else { return nil }
                        var req = URLRequest(url: url, timeoutInterval: timeoutSec)
                        req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                        guard let (data, response) = try? await session.data(for: req),
                              (response as? HTTPURLResponse)?.statusCode == 200,
                              let ip = String(data: data, encoding: .utf8)?
                                .trimmingCharacters(in: .whitespacesAndNewlines) else { continue }
                        if family.ipv6 ? IPv6Address(ip) != nil : IPv4Address(ip) != nil { return canonicalIp(ip) }
                    }
                    return nil
                }
            }
            var found = Set<String>()
            for await ip in group {
                if let ip { found.insert(ip) }
            }
            return found
        }
    }

    /// RFC 5952 form for IPv6 so addresses from different services compare equal.
    static func canonicalIp(_ raw: String) -> String {
        let ip = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ip.contains(":") else { return ip }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, ip, &addr) == 1 else { return ip.lowercased() }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &addr, &buffer, socklen_t(buffer.count)) != nil else { return ip.lowercased() }
        return String(cString: buffer)
    }

    static func geo(corePort: Int, expectedIP: String) async -> (city: String?, org: String?)? {
        guard let url = URL(string: "https://ipwho.is/") else { return nil }
        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: 4)
        defer { session.invalidateAndCancel() }
        guard let (data, response) = try? await session.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              (obj["ip"] as? String).map(canonicalIp) == canonicalIp(expectedIP) else { return nil }
        let connection = obj["connection"] as? [String: Any]
        return (obj["city"] as? String, (connection?["isp"] as? String) ?? (connection?["org"] as? String))
    }
}
