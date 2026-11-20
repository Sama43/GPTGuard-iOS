import Foundation
import SwiftUI

/// Risk level derived from ChatGPT's `proofofwork.difficulty` (sentinel/chat-requirements).
/// Thresholds are community experience, not an official standard:
/// after stripping `0x` and leading zeros, >=5 significant hex digits = normal, 4 = fair, 3 = elevated, <=2 = high.
enum PowRisk: Int, Codable, Comparable {
    case normal = 0, fair, elevated, high

    static func < (lhs: PowRisk, rhs: PowRisk) -> Bool { lhs.rawValue < rhs.rawValue }

    static func significantDigits(_ difficulty: String) -> Int {
        var hex = difficulty.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if hex.hasPrefix("0x") { hex.removeFirst(2) }
        return String(hex.drop { $0 == "0" }).count
    }

    init(difficulty: String) {
        switch PowRisk.significantDigits(difficulty) {
        case 5...: self = .normal
        case 4: self = .fair
        case 3: self = .elevated
        default: self = .high
        }
    }

    var title: String {
        switch self {
        case .normal: return "正常"
        case .fair: return "一般"
        case .elevated: return "偏高风险"
        case .high: return "高风险 · 大概率降智"
        }
    }

    var advice: String {
        switch self {
        case .normal: return "PoW 难度正常，当前出口未被明显限流。"
        case .fair: return "难度略高，模型通常正常，可留意回复质量。"
        case .elevated: return "难度偏高，可能被降级。建议换更干净的独享 / 住宅节点后清除网页数据重新登录。"
        case .high: return "难度很高，大概率已降智（被分配更弱模型或关闭联网/画图等功能）。建议立即更换节点。"
        }
    }

    var color: Color {
        switch self {
        case .normal: return VpnTheme.shieldGreen
        case .fair: return Color.yellow
        case .elevated: return VpnTheme.warnAmber
        case .high: return VpnTheme.killRed
        }
    }
}

struct PowRecord: Identifiable, Codable, Equatable {
    var id = UUID()
    var date = Date()
    var difficulty: String
    var risk: PowRisk
    var turnstileRequired = false
    var arkoseRequired = false
    var persona: String = ""
    var exitIp: String?
}

enum OverallVerdict {
    case unknown, good, caution, degraded

    var title: String {
        switch self {
        case .unknown: return "尚未检测"
        case .good: return "正常，未见降智迹象"
        case .caution: return "有降智风险"
        case .degraded: return "大概率已降智"
        }
    }

    var color: Color {
        switch self {
        case .unknown: return VpnTheme.textSecondary
        case .good: return VpnTheme.shieldGreen
        case .caution: return VpnTheme.warnAmber
        case .degraded: return VpnTheme.killRed
        }
    }
}

@MainActor
final class DiagnosticsStore: ObservableObject {
    @Published private(set) var report: IPPurityReport?
    @Published private(set) var timezone: TimezoneCheck?
    @Published private(set) var lastError: String?
    @Published private(set) var running = false
    @Published private(set) var powRecords: [PowRecord] = []
    /// Set when a new exit IP's timezone disagrees with the device; drives a one-shot alert.
    @Published var timezoneAlert: TimezoneCheck?

    private var alertedIps = Set<String>()
    private var runTask: Task<Void, Never>?
    private let powKey = "gptguard_pow_records_v1"

    init() {
        if let data = UserDefaults.standard.data(forKey: powKey),
           let saved = try? JSONDecoder().decode([PowRecord].self, from: data) {
            powRecords = saved
        }
    }

    var latestPow: PowRecord? { powRecords.first }

    /// PoW measured within the last 6 hours, if any (older readings no longer describe the current exit).
    private var recentPow: PowRecord? {
        guard let pow = latestPow, Date().timeIntervalSince(pow.date) < 6 * 3600 else { return nil }
        if let ip = report?.trace.ip, let powIp = pow.exitIp, ip != powIp { return nil }
        return pow
    }

    var verdict: OverallVerdict {
        if let pow = recentPow {
            switch pow.risk {
            case .high: return .degraded
            case .elevated: return .caution
            case .fair, .normal:
                if let report, report.score < 40 { return .caution }
                return .good
            }
        }
        guard let report else { return .unknown }
        if IPPurityChecker.unsupportedRegions.contains(report.countryCode ?? "") { return .degraded }
        switch report.grade {
        case .clean, .fair: return .good
        case .poor: return .caution
        case .risky: return .degraded
        }
    }

    var verdictDetail: String {
        var parts: [String] = []
        if let pow = recentPow {
            parts.append("PoW 实测：\(pow.risk.title)（难度 \(pow.difficulty)）")
        } else {
            parts.append("还没有 PoW 实测数据：在「检测 › 网页版 ChatGPT」里发一条消息即可测得（结论最准）")
        }
        if let report {
            parts.append("IP 纯净度 \(report.score) 分（\(report.grade.title)）")
        }
        if let tz = timezone, tz.status == .mismatch {
            parts.append("时区与 IP 不吻合")
        }
        return parts.joined(separator: "\n")
    }

    func run() {
        runTask?.cancel()
        running = true
        lastError = nil
        runTask = Task {
            do {
                let result = try await IPPurityChecker.run()
                guard !Task.isCancelled else { return }
                self.report = result
                let tz = TimezoneCheck.compare(ipTimezone: result.timezoneId)
                self.timezone = tz
                if tz.status == .mismatch, !self.alertedIps.contains(result.trace.ip) {
                    self.alertedIps.insert(result.trace.ip)
                    self.timezoneAlert = tz
                }
            } catch {
                guard !Task.isCancelled else { return }
                self.lastError = error.localizedDescription
            }
            self.running = false
        }
    }

    func recordPow(difficulty: String, turnstile: Bool, arkose: Bool, persona: String) {
        let record = PowRecord(difficulty: difficulty, risk: PowRisk(difficulty: difficulty),
                               turnstileRequired: turnstile, arkoseRequired: arkose,
                               persona: persona, exitIp: report?.trace.ip)
        powRecords.insert(record, at: 0)
        if powRecords.count > 100 { powRecords = Array(powRecords.prefix(100)) }
        savePow()
    }

    func clearPowHistory() {
        powRecords = []
        savePow()
    }

    private func savePow() {
        if let data = try? JSONEncoder().encode(powRecords) {
            UserDefaults.standard.set(data, forKey: powKey)
        }
    }
}
