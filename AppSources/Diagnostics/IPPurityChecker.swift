import Foundation
import Network

/// Result of a Cloudflare `/cdn-cgi/trace` request: the address a Cloudflare-fronted site (ChatGPT) sees.
struct TraceInfo: Codable, Equatable {
    var ip: String
    var loc: String?
    var colo: String?
    var warp: String?
    /// Host the trace was served by (chatgpt.com, or the cloudflare.com fallback).
    var source: String
}

struct PurityRiskItem: Identifiable, Codable, Equatable {
    var id = UUID()
    var title: String
    var detail: String
    var penalty: Int
}

struct IPPurityReport: Codable, Equatable {
    var trace: TraceInfo
    var countryCode: String?
    var country: String?
    var city: String?
    var timezoneId: String?
    /// Which lookup supplied `timezoneId`.
    var timezoneSource: String?
    /// Other sources reported a timezone with a different UTC offset (geo databases disagree).
    var timezoneConflict: String?
    var org: String?
    var companyType: String?
    var abuserScore: String?
    var isDatacenter = false
    var isVPN = false
    var isProxy = false
    var isTor = false
    var isAbuser = false
    var isMobile = false
    /// proxycheck.io connection type (Residential / Wireless / Business / Hosting / VPN / TOR ...).
    var connectionType: String?
    /// proxycheck.io risk score 0-100.
    var riskScore: Int?
    /// Lookup services that answered.
    var sources: [String] = []
    /// false when no source with datacenter / VPN / proxy flags answered.
    var hasReputation = false
    var risks: [PurityRiskItem] = []
    var score = 100
    var checkedAt = Date()

    var grade: PurityGrade { PurityGrade(score: score) }
}

enum PurityGrade {
    case clean, fair, poor, risky

    init(score: Int) {
        switch score {
        case 80...: self = .clean
        case 60..<80: self = .fair
        case 40..<60: self = .poor
        default: self = .risky
        }
    }

    var title: String {
        switch self {
        case .clean: return "纯净"
        case .fair: return "一般"
        case .poor: return "较差"
        case .risky: return "高风险"
        }
    }
}

struct TimezoneCheck: Equatable {
    enum Status { case match, sameOffset, mismatch, unknown }

    var deviceId: String
    var deviceOffsetSec: Int
    var ipId: String?
    var ipOffsetSec: Int?
    var status: Status

    static func compare(ipTimezone: String?, now: Date = Date()) -> TimezoneCheck {
        let device = TimeZone.current
        let deviceOffset = device.secondsFromGMT(for: now)
        guard let id = ipTimezone, !id.isEmpty, let ipZone = TimeZone(identifier: id) else {
            return TimezoneCheck(deviceId: device.identifier, deviceOffsetSec: deviceOffset, ipId: ipTimezone, ipOffsetSec: nil, status: .unknown)
        }
        let ipOffset = ipZone.secondsFromGMT(for: now)
        let status: Status
        if ipZone.identifier == device.identifier {
            status = .match
        } else if ipOffset == deviceOffset {
            status = .sameOffset
        } else {
            status = .mismatch
        }
        return TimezoneCheck(deviceId: device.identifier, deviceOffsetSec: deviceOffset, ipId: ipZone.identifier, ipOffsetSec: ipOffset, status: status)
    }

    static func formatOffset(_ seconds: Int) -> String {
        let sign = seconds >= 0 ? "+" : "-"
        let total = abs(seconds) / 60
        return String(format: "UTC%@%02d:%02d", sign, total / 60, total % 60)
    }

    var hourDifference: Double? {
        guard let ipOffsetSec else { return nil }
        return Double(ipOffsetSec - deviceOffsetSec) / 3600
    }
}

enum IPPurityChecker {
    /// Common regions where OpenAI does not offer service (incomplete; used as a hint only).
    static let unsupportedRegions: Set<String> = ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU"]

    /// Optional ipapi.is API key (free sign-up). Without it ipapi.is only returns geo + company (no flags).
    static let ipapiKeyDefaultsKey = "gptguard_ipapi_key"

    private static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 12
        config.timeoutIntervalForResource = 15
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: config)
    }

    static func run() async throws -> IPPurityReport {
        let session = makeSession()
        defer { session.finishTasksAndInvalidate() }

        let trace = try await fetchTrace(session: session)
        var report = IPPurityReport(trace: trace, countryCode: trace.loc)
        let key = (UserDefaults.standard.string(forKey: ipapiKeyDefaultsKey) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // Query the three sources concurrently; each one is optional.
        async let ipapiResult = try? lookupIpapi(ip: trace.ip, key: key, session: session)
        async let proxycheckResult = try? lookupProxycheck(ip: trace.ip, session: session)
        async let ipApiComResult = try? lookupIpApiCom(ip: trace.ip, session: session)
        let ipapi = await ipapiResult?.object
        let proxycheck = await proxycheckResult?.object
        let ipApiCom = await ipApiComResult?.object

        var zones: [(id: String, source: String)] = []
        if let obj = ipapi, let tz = apply(ipapi: obj, to: &report) { zones.append((tz, "ipapi.is")) }
        if let obj = proxycheck, let tz = apply(proxycheck: obj, to: &report) { zones.append((tz, "proxycheck.io")) }
        if let obj = ipApiCom, let tz = apply(ipApiCom: obj, to: &report) { zones.append((tz, "ip-api.com")) }

        if let first = zones.first {
            report.timezoneId = first.id
            report.timezoneSource = first.source
            let now = Date()
            let offset = TimeZone(identifier: first.id)?.secondsFromGMT(for: now)
            let others = zones.dropFirst().filter { TimeZone(identifier: $0.id)?.secondsFromGMT(for: now) != offset }
            if !others.isEmpty {
                report.timezoneConflict = others.map { "\($0.source): \($0.id)" }.joined(separator: "，")
            }
        }
        score(&report)
        return report
    }

    // MARK: - Trace

    private static func fetchTrace(session: URLSession) async throws -> TraceInfo {
        var lastError: Error = URLError(.cannotConnectToHost)
        for host in ["chatgpt.com", "www.cloudflare.com"] {
            guard let url = URL(string: "https://\(host)/cdn-cgi/trace") else { continue }
            do {
                var request = URLRequest(url: url)
                request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                let (data, response) = try await session.data(for: request)
                guard (response as? HTTPURLResponse)?.statusCode == 200,
                      let text = String(data: data, encoding: .utf8) else { throw URLError(.badServerResponse) }
                var map: [String: String] = [:]
                for line in text.components(separatedBy: .newlines) {
                    let parts = line.split(separator: "=", maxSplits: 1)
                    if parts.count == 2 { map[String(parts[0])] = String(parts[1]).trimmingCharacters(in: .whitespaces) }
                }
                guard let ip = map["ip"], IPv4Address(ip) != nil || IPv6Address(ip) != nil else {
                    throw URLError(.cannotParseResponse)
                }
                return TraceInfo(ip: ip, loc: map["loc"]?.uppercased(), colo: map["colo"], warp: map["warp"], source: host)
            } catch {
                lastError = error
            }
        }
        throw NSError(domain: "IPPurity", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "无法连到 ChatGPT（若 VPN 处于黑洞熔断状态，这是预期行为）：\(lastError.localizedDescription)"
        ])
    }

    // MARK: - Reputation lookups

    /// JSONSerialization output is immutable once parsed; boxed so it can cross `async let` boundaries.
    private struct JSONBox: @unchecked Sendable {
        let object: [String: Any]
    }

    private static func fetchJSON(_ urlString: String, session: URLSession) async throws -> [String: Any] {
        guard let url = URL(string: urlString) else { throw URLError(.badURL) }
        var request = URLRequest(url: url)
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        return obj
    }

    private static func encoded(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
    }

    /// ipapi.is: keyless responses are flat (`timezone`, `company`, `country` strings; flags removed 2026-09).
    /// Keyed responses are nested and include is_datacenter / is_vpn / ... flags.
    private static func lookupIpapi(ip: String, key: String, session: URLSession) async throws -> JSONBox {
        var url = "https://api.ipapi.is/?q=\(encoded(ip))"
        if !key.isEmpty { url += "&key=\(encoded(key))" }
        let obj = try await fetchJSON(url, session: session)
        guard obj["error"] == nil, obj["ip"] != nil else { throw URLError(.badServerResponse) }
        return JSONBox(object: obj)
    }

    /// proxycheck.io v2 (HTTPS, no key needed for light use).
    private static func lookupProxycheck(ip: String, session: URLSession) async throws -> JSONBox {
        let obj = try await fetchJSON("https://proxycheck.io/v2/\(encoded(ip))?vpn=1&asn=1&risk=1", session: session)
        if (obj["status"] as? String)?.lowercased() == "error" { throw URLError(.badServerResponse) }
        if let entry = obj[ip] as? [String: Any] { return JSONBox(object: entry) }
        if let entry = obj.values.compactMap({ $0 as? [String: Any] }).first(where: { $0["proxy"] != nil }) {
            return JSONBox(object: entry)
        }
        throw URLError(.badServerResponse)
    }

    /// ip-api.com free endpoint (HTTP only on the free tier; ATS exception declared in Info.plist).
    private static func lookupIpApiCom(ip: String, session: URLSession) async throws -> JSONBox {
        let fields = "status,message,countryCode,country,city,timezone,isp,org,mobile,proxy,hosting"
        let obj = try await fetchJSON("http://ip-api.com/json/\(encoded(ip))?fields=\(fields)", session: session)
        guard obj["status"] as? String == "success" else { throw URLError(.badServerResponse) }
        return JSONBox(object: obj)
    }

    private static func bool(_ obj: [String: Any], _ key: String) -> Bool {
        if let b = obj[key] as? Bool { return b }
        if let n = obj[key] as? NSNumber { return n.boolValue }
        if let s = obj[key] as? String { return ["yes", "true", "1"].contains(s.lowercased()) }
        return false
    }

    private static func text(_ value: Any?) -> String? {
        guard let s = value as? String, !s.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return s
    }

    /// Each `apply` merges one source into the report and returns the timezone it reported, if any.
    private static func apply(ipapi obj: [String: Any], to report: inout IPPurityReport) -> String? {
        report.sources.append("ipapi.is")
        var timezone: String?
        if let location = obj["location"] as? [String: Any] {
            report.countryCode = text(location["country_code"])?.uppercased() ?? report.countryCode
            report.country = text(location["country"]) ?? report.country
            report.city = text(location["city"]) ?? report.city
            timezone = text(location["timezone"])
        } else {
            report.country = text(obj["country"]) ?? report.country
            report.city = text(obj["city"]) ?? report.city
            timezone = text(obj["timezone"])
        }
        if let company = obj["company"] as? [String: Any] {
            report.org = text(company["name"]) ?? report.org
            report.companyType = text(company["type"])
            report.abuserScore = text(company["abuser_score"])
        } else if let company = text(obj["company"]) {
            report.org = report.org ?? company
        }
        if obj["is_datacenter"] != nil || obj["is_vpn"] != nil {
            report.hasReputation = true
            report.isDatacenter = report.isDatacenter || bool(obj, "is_datacenter")
            report.isVPN = report.isVPN || bool(obj, "is_vpn")
            report.isProxy = report.isProxy || bool(obj, "is_proxy")
            report.isTor = report.isTor || bool(obj, "is_tor")
            report.isAbuser = report.isAbuser || bool(obj, "is_abuser")
            report.isMobile = report.isMobile || bool(obj, "is_mobile")
        }
        return timezone
    }

    private static func apply(proxycheck obj: [String: Any], to report: inout IPPurityReport) -> String? {
        report.sources.append("proxycheck.io")
        report.hasReputation = true
        report.countryCode = report.countryCode ?? text(obj["isocode"])?.uppercased()
        report.country = report.country ?? text(obj["country"])
        report.city = report.city ?? text(obj["city"])
        report.org = report.org ?? text(obj["organisation"]) ?? text(obj["provider"])
        let type = text(obj["type"])
        report.connectionType = type
        if let risk = obj["risk"] as? NSNumber {
            report.riskScore = risk.intValue
        } else if let risk = text(obj["risk"]).flatMap({ Int($0) }) {
            report.riskScore = risk
        }
        let lowered = type?.lowercased() ?? ""
        if lowered == "hosting" { report.isDatacenter = true }
        if lowered == "vpn" { report.isVPN = true }
        if lowered == "tor" { report.isTor = true }
        if lowered == "wireless" { report.isMobile = true }
        if bool(obj, "proxy"), lowered != "vpn", lowered != "tor" { report.isProxy = true }
        return text(obj["timezone"])
    }

    private static func apply(ipApiCom obj: [String: Any], to report: inout IPPurityReport) -> String? {
        report.sources.append("ip-api.com")
        report.hasReputation = true
        report.countryCode = report.countryCode ?? text(obj["countryCode"])?.uppercased()
        report.country = report.country ?? text(obj["country"])
        report.city = report.city ?? text(obj["city"])
        report.org = report.org ?? text(obj["isp"]) ?? text(obj["org"])
        if bool(obj, "hosting") { report.isDatacenter = true }
        if bool(obj, "proxy") { report.isProxy = true }
        if bool(obj, "mobile") { report.isMobile = true }
        return text(obj["timezone"])
    }

    // MARK: - Scoring (community heuristics, not an official OpenAI standard)

    private static func score(_ report: inout IPPurityReport) {
        var risks: [PurityRiskItem] = []
        let cc = report.countryCode ?? report.trace.loc ?? ""
        if unsupportedRegions.contains(cc) {
            risks.append(PurityRiskItem(title: "不支持地区", detail: "ChatGPT 看到的地区是 \(cc)，属于常见的不支持地区", penalty: 50))
        }
        if report.isTor {
            risks.append(PurityRiskItem(title: "Tor 出口", detail: "该 IP 是 Tor 出口节点", penalty: 60))
        }
        if report.isDatacenter {
            let org = report.org.map { "（\($0)）" } ?? ""
            risks.append(PurityRiskItem(title: "机房 IP", detail: "IP 属于数据中心 / 云主机\(org)，多人共用概率高", penalty: 35))
        }
        if report.isVPN {
            risks.append(PurityRiskItem(title: "VPN 标记", detail: "IP 被信誉库标记为 VPN", penalty: 30))
        }
        if report.isProxy {
            risks.append(PurityRiskItem(title: "代理标记", detail: "IP 被信誉库标记为代理", penalty: 25))
        }
        if report.isAbuser {
            let s = report.abuserScore.map { "（滥用分 \($0)）" } ?? ""
            risks.append(PurityRiskItem(title: "滥用记录", detail: "该 IP 段有滥用 / 攻击记录\(s)", penalty: 30))
        }
        if let risk = report.riskScore {
            if risk >= 67 {
                risks.append(PurityRiskItem(title: "高风险评分", detail: "proxycheck.io 风险分 \(risk)/100（近期有攻击 / 滥用行为）", penalty: 30))
            } else if risk >= 34 {
                risks.append(PurityRiskItem(title: "中等风险评分", detail: "proxycheck.io 风险分 \(risk)/100", penalty: 10))
            }
        }
        if report.trace.warp == "on" || report.trace.warp == "plus" {
            risks.append(PurityRiskItem(title: "Cloudflare WARP", detail: "当前通过 WARP 访问，共享出口通常风险较高", penalty: 15))
        }
        report.risks = risks
        report.score = max(0, 100 - risks.reduce(0) { $0 + $1.penalty })
        report.checkedAt = Date()
    }
}
