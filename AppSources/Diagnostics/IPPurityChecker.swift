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
    var org: String?
    var companyType: String?
    var abuserScore: String?
    var isDatacenter = false
    var isVPN = false
    var isProxy = false
    var isTor = false
    var isAbuser = false
    var isMobile = false
    /// false when only the fallback geo source answered (no datacenter / VPN reputation data).
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

        if let info = try? await lookupIpapi(ip: trace.ip, session: session) {
            apply(ipapi: info, to: &report)
        } else if let info = try? await lookupIpwho(ip: trace.ip, session: session) {
            apply(ipwho: info, to: &report)
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

    private static func fetchJSON(_ urlString: String, session: URLSession) async throws -> [String: Any] {
        guard let url = URL(string: urlString) else { throw URLError(.badURL) }
        let (data, response) = try await session.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }
        return obj
    }

    private static func encoded(_ ip: String) -> String {
        ip.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ip
    }

    private static func lookupIpapi(ip: String, session: URLSession) async throws -> [String: Any] {
        let obj = try await fetchJSON("https://api.ipapi.is/?q=\(encoded(ip))", session: session)
        guard obj["error"] == nil else { throw URLError(.badServerResponse) }
        return obj
    }

    private static func lookupIpwho(ip: String, session: URLSession) async throws -> [String: Any] {
        let obj = try await fetchJSON("https://ipwho.is/\(encoded(ip))", session: session)
        guard obj["success"] as? Bool != false else { throw URLError(.badServerResponse) }
        return obj
    }

    private static func bool(_ obj: [String: Any], _ key: String) -> Bool {
        if let b = obj[key] as? Bool { return b }
        if let n = obj[key] as? NSNumber { return n.boolValue }
        return false
    }

    private static func apply(ipapi obj: [String: Any], to report: inout IPPurityReport) {
        report.hasReputation = true
        report.isDatacenter = bool(obj, "is_datacenter")
        report.isVPN = bool(obj, "is_vpn")
        report.isProxy = bool(obj, "is_proxy")
        report.isTor = bool(obj, "is_tor")
        report.isAbuser = bool(obj, "is_abuser")
        report.isMobile = bool(obj, "is_mobile")
        if let company = obj["company"] as? [String: Any] {
            report.org = company["name"] as? String
            report.companyType = company["type"] as? String
            report.abuserScore = company["abuser_score"] as? String
        }
        if report.org == nil, let asn = obj["asn"] as? [String: Any] {
            report.org = asn["org"] as? String
        }
        if let location = obj["location"] as? [String: Any] {
            report.countryCode = (location["country_code"] as? String)?.uppercased() ?? report.countryCode
            report.country = location["country"] as? String
            report.city = location["city"] as? String
            report.timezoneId = location["timezone"] as? String
        }
    }

    private static func apply(ipwho obj: [String: Any], to report: inout IPPurityReport) {
        report.countryCode = (obj["country_code"] as? String)?.uppercased() ?? report.countryCode
        report.country = obj["country"] as? String
        report.city = obj["city"] as? String
        if let tz = obj["timezone"] as? [String: Any] { report.timezoneId = tz["id"] as? String }
        if let connection = obj["connection"] as? [String: Any] {
            report.org = (connection["isp"] as? String) ?? (connection["org"] as? String)
        }
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
        if report.trace.warp == "on" || report.trace.warp == "plus" {
            risks.append(PurityRiskItem(title: "Cloudflare WARP", detail: "当前通过 WARP 访问，共享出口通常风险较高", penalty: 15))
        }
        report.risks = risks
        report.score = max(0, 100 - risks.reduce(0) { $0 + $1.penalty })
        report.checkedAt = Date()
    }
}
