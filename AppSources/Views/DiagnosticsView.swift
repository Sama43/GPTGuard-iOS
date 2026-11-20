import SwiftUI
import UIKit

struct DiagnosticsView: View {
    @ObservedObject var engine: VpnManagerEngine
    @ObservedObject var diagnostics: DiagnosticsStore

    @State private var confirmClear = false
    @State private var copiedPrompt = false
    @State private var webDataCleared = false

    private static let selfTestPrompt = "请用表格列出你当前可用的全部工具（例如联网搜索、画图、代码解释器、文件分析、记忆等），以及你当前的模型名称。"

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    verdictCard
                    purityCard
                    timezoneCard
                    powCard
                    selfTestCard
                }
                .padding()
            }
            .refreshable { diagnostics.run() }
            .background(VpnTheme.bgDark.ignoresSafeArea())
            .navigationTitle("降智 / IP 纯净度检测")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { diagnostics.run() } label: {
                        if diagnostics.running { ProgressView() } else { Image(systemName: "arrow.clockwise") }
                    }
                    .disabled(diagnostics.running)
                }
            }
            .onAppear { if diagnostics.report == nil && !diagnostics.running { diagnostics.run() } }
            .alert("清除网页版 ChatGPT 的全部数据？", isPresented: $confirmClear) {
                Button("取消", role: .cancel) {}
                Button("清除", role: .destructive) {
                    Task {
                        await ChatGPTWebData.clearAll()
                        webDataCleared = true
                    }
                }
            } message: {
                Text("会退出网页版登录并清除 Cookie / 缓存（不影响 Safari 和官方 App）。换节点后清除再登录，可避免旧风控标记沿用。")
            }
        }
    }

    // MARK: - Cards

    private var verdictCard: some View {
        let verdict = diagnostics.verdict
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: verdict == .good ? "checkmark.seal.fill" : (verdict == .unknown ? "questionmark.circle" : "exclamationmark.triangle.fill"))
                    .font(.title2)
                    .foregroundStyle(verdict.color)
                Text(verdict.title).font(.headline).foregroundStyle(verdict.color)
                Spacer()
            }
            Text(diagnostics.verdictDetail)
                .font(.caption)
                .foregroundStyle(VpnTheme.textSecondary)
                .lineSpacing(3)
            if engine.vpnStatus != .connected {
                Text("提示：VPN 未连接，以下结果反映的是你当前的直连网络。")
                    .font(.caption2).foregroundStyle(VpnTheme.warnAmber)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(verdict.color.opacity(0.6), lineWidth: 1.2))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private var purityCard: some View {
        card(title: "IP 出口纯净度", icon: "network.badge.shield.half.filled") {
            if let report = diagnostics.report {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("\(report.score)")
                        .font(.system(size: 40, weight: .bold, design: .rounded))
                        .foregroundStyle(gradeColor(report.grade))
                    Text("/ 100 · \(report.grade.title)")
                        .font(.subheadline.bold())
                        .foregroundStyle(gradeColor(report.grade))
                    Spacer()
                }
                kv("ChatGPT 看到的 IP", report.trace.ip)
                kv("地区", [report.countryCode, report.country, report.city].compactMap { $0 }.joined(separator: " · "))
                kv("运营商 / 机构", [report.org, report.companyType].compactMap { $0 }.joined(separator: " · "))
                kv("Cloudflare 节点", [report.trace.colo, report.trace.warp.map { "WARP \($0)" }].compactMap { $0 }.joined(separator: " · "))
                if let abuser = report.abuserScore { kv("滥用评分", abuser) }
                if let direct = engine.snapshot.directIp, engine.vpnStatus == .connected {
                    kv("本机直连 IP", direct)
                }
                if report.hasReputation {
                    flagRow(report)
                } else {
                    Text("信誉库（ipapi.is）暂不可用，仅显示地理信息，分数只计算了地区。")
                        .font(.caption2).foregroundStyle(VpnTheme.warnAmber)
                }
                if report.risks.isEmpty {
                    Text("未发现风险项").font(.caption).foregroundStyle(VpnTheme.shieldGreen)
                } else {
                    ForEach(report.risks) { risk in
                        HStack(alignment: .top, spacing: 6) {
                            Text("-\(risk.penalty)").font(.caption.monospacedDigit().bold()).foregroundStyle(VpnTheme.killRed)
                                .frame(width: 34, alignment: .leading)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(risk.title).font(.caption.bold()).foregroundStyle(VpnTheme.textPrimary)
                                Text(risk.detail).font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                            }
                        }
                    }
                }
                Text("检测于 \(report.checkedAt.formatted(date: .omitted, time: .standard)) · 评分为社区经验规则，仅供参考")
                    .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
            } else if let error = diagnostics.lastError {
                Text(error).font(.caption).foregroundStyle(VpnTheme.killRed)
            } else {
                HStack { ProgressView(); Text("正在检测…").font(.caption).foregroundStyle(VpnTheme.textSecondary) }
            }
            if diagnostics.report != nil, let error = diagnostics.lastError {
                Text("最近一次刷新失败：\(error)").font(.caption2).foregroundStyle(VpnTheme.warnAmber)
            }
        }
    }

    private var timezoneCard: some View {
        card(title: "时区一致性", icon: "clock.badge.questionmark") {
            if let tz = diagnostics.timezone {
                HStack(spacing: 8) {
                    Image(systemName: tzIcon(tz.status)).foregroundStyle(tzColor(tz.status))
                    Text(tzTitle(tz)).font(.subheadline.bold()).foregroundStyle(tzColor(tz.status))
                    Spacer()
                }
                kv("本机时区", "\(tz.deviceId) · \(TimezoneCheck.formatOffset(tz.deviceOffsetSec))")
                kv("IP 所在时区", tz.ipId.map { id in "\(id) · \(tz.ipOffsetSec.map(TimezoneCheck.formatOffset) ?? "?")" } ?? "未知")
                if tz.status == .mismatch {
                    Text("IP 所在地与本机时区不一致，部分服务会把这种不一致当作风险信号。可选择与本机时区相同地区的节点，或在「设置 › 通用 › 日期与时间」中核对时区。")
                        .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
            } else {
                Text("完成 IP 检测后显示").font(.caption).foregroundStyle(VpnTheme.textSecondary)
            }
        }
    }

    private var powCard: some View {
        card(title: "PoW 降智实测（最准）", icon: "gauge.with.dots.needle.67percent") {
            if let pow = diagnostics.latestPow {
                HStack(spacing: 8) {
                    Circle().fill(pow.risk.color).frame(width: 10, height: 10)
                    Text(pow.risk.title).font(.subheadline.bold()).foregroundStyle(pow.risk.color)
                    Spacer()
                    Text(pow.date.formatted(date: .abbreviated, time: .shortened)).font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
                kv("difficulty", "\(pow.difficulty)（有效位 \(PowRisk.significantDigits(pow.difficulty))）")
                if pow.turnstileRequired || pow.arkoseRequired {
                    kv("额外人机验证", [pow.turnstileRequired ? "Turnstile" : nil, pow.arkoseRequired ? "Arkose" : nil].compactMap { $0 }.joined(separator: " + "))
                }
                if !pow.persona.isEmpty { kv("账号类型", pow.persona) }
                Text(pow.risk.advice).font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                if diagnostics.powRecords.count > 1 {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("历史记录").font(.caption2.bold()).foregroundStyle(VpnTheme.textSecondary)
                        ForEach(diagnostics.powRecords.prefix(8)) { r in
                            HStack(spacing: 6) {
                                Circle().fill(r.risk.color).frame(width: 6, height: 6)
                                Text(r.date.formatted(date: .omitted, time: .shortened)).font(.caption2.monospacedDigit())
                                Text(r.difficulty).font(.caption2.monospaced())
                                Spacer()
                                Text(r.exitIp ?? "").font(.caption2).lineLimit(1)
                            }
                            .foregroundStyle(VpnTheme.textSecondary)
                        }
                    }
                }
            } else {
                Text("打开下方网页版 ChatGPT，登录后随便发一条消息，App 会读取服务器下发的 PoW 难度并判断是否降智。")
                    .font(.caption).foregroundStyle(VpnTheme.textSecondary)
            }
            NavigationLink {
                ChatGPTWebScreen(diagnostics: diagnostics)
            } label: {
                Label("打开网页版 ChatGPT 实测", systemImage: "safari")
                    .font(.subheadline.bold())
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .background(VpnTheme.accentTeal).foregroundStyle(VpnTheme.bgDark)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            HStack(spacing: 8) {
                smallButton(webDataCleared ? "已清除网页数据" : "清除网页数据", role: .destructive) { confirmClear = true }
                smallButton("清空历史") { diagnostics.clearPowHistory() }
            }
            Text("网页版使用独立的数据存储（与 Safari 隔离），流量与官方 App 走同一条受保护出口。iOS 沙盒限制下无法读取官方 App 内部流量，因此用网页版代测。")
                .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
        }
    }

    private var selfTestCard: some View {
        card(title: "手动自测", icon: "text.bubble") {
            Text("在官方 App 里发送下面这段话。被降智时，通常只剩一两个工具、或回答明显变弱。")
                .font(.caption).foregroundStyle(VpnTheme.textSecondary)
            Text(Self.selfTestPrompt)
                .font(.caption.monospaced())
                .foregroundStyle(VpnTheme.textPrimary)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(VpnTheme.cardDark)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            smallButton(copiedPrompt ? "已复制" : "复制提示词") {
                UIPasteboard.general.string = Self.selfTestPrompt
                copiedPrompt = true
            }
        }
    }

    // MARK: - Helpers

    private func card<Content: View>(title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon).font(.subheadline.bold()).foregroundStyle(VpnTheme.accentTeal)
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(VpnTheme.borderDark, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private func kv(_ key: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(key).font(.caption).foregroundStyle(VpnTheme.textSecondary)
            Spacer(minLength: 12)
            Text(value.isEmpty ? "—" : value)
                .font(.caption.bold())
                .foregroundStyle(VpnTheme.textPrimary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }

    private func flagRow(_ report: IPPurityReport) -> some View {
        let flags: [(String, Bool, Bool)] = [
            ("机房", report.isDatacenter, true),
            ("VPN", report.isVPN, true),
            ("代理", report.isProxy, true),
            ("Tor", report.isTor, true),
            ("滥用", report.isAbuser, true),
            ("移动网络", report.isMobile, false)
        ]
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(flags.indices, id: \.self) { index in
                    let (name, on, bad) = flags[index]
                    let color = on ? (bad ? VpnTheme.killRed : VpnTheme.shieldGreen) : VpnTheme.textSecondary
                    Text("\(on ? "是" : "否") · \(name)")
                        .font(.caption2.bold())
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .foregroundStyle(color)
                        .background(on ? color.opacity(0.15) : VpnTheme.cardDark)
                        .clipShape(Capsule())
                }
            }
        }
    }

    private func smallButton(_ title: String, role: ButtonRole? = nil, action: @escaping () -> Void) -> some View {
        Button(role: role, action: action) {
            Text(title)
                .font(.caption.bold())
                .frame(maxWidth: .infinity).padding(.vertical, 8)
                .background(VpnTheme.cardDark)
                .foregroundStyle(role == .destructive ? VpnTheme.killRed : VpnTheme.textPrimary)
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private func gradeColor(_ grade: PurityGrade) -> Color {
        switch grade {
        case .clean: return VpnTheme.shieldGreen
        case .fair: return Color.yellow
        case .poor: return VpnTheme.warnAmber
        case .risky: return VpnTheme.killRed
        }
    }

    private func tzIcon(_ status: TimezoneCheck.Status) -> String {
        switch status {
        case .match, .sameOffset: return "checkmark.circle.fill"
        case .mismatch: return "exclamationmark.triangle.fill"
        case .unknown: return "questionmark.circle"
        }
    }

    private func tzColor(_ status: TimezoneCheck.Status) -> Color {
        switch status {
        case .match: return VpnTheme.shieldGreen
        case .sameOffset: return Color.yellow
        case .mismatch: return VpnTheme.killRed
        case .unknown: return VpnTheme.textSecondary
        }
    }

    private func tzTitle(_ tz: TimezoneCheck) -> String {
        switch tz.status {
        case .match: return "吻合"
        case .sameOffset: return "时差一致（时区名称不同）"
        case .mismatch:
            let diff = tz.hourDifference.map { String(format: "%+.1f 小时", $0) } ?? ""
            return "不吻合 · 相差 \(diff)"
        case .unknown: return "无法获取 IP 时区"
        }
    }
}
