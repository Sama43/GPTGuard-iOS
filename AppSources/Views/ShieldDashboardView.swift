import SwiftUI
import UIKit

struct ShieldDashboardView: View {
    @ObservedObject var engine: VpnManagerEngine
    @ObservedObject var diagnostics: DiagnosticsStore
    @Binding var selectedTab: Int

    private var statusColor: Color {
        switch engine.snapshot.status {
        case .protected: return VpnTheme.shieldGreen
        case .blackholeKillSwitch: return VpnTheme.killRed
        case .startingCore, .verifyingExit: return VpnTheme.warnAmber
        case .stopped: return VpnTheme.textSecondary
        }
    }

    private var statusBg: Color {
        switch engine.snapshot.status {
        case .protected: return VpnTheme.shieldGreenBg
        case .blackholeKillSwitch: return VpnTheme.killRedBg
        case .startingCore, .verifyingExit: return VpnTheme.warnAmberBg
        case .stopped: return VpnTheme.cardDark
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    heroCard
                    diagnosticsCard
                    modeCard
                    architectureNoteCard
                }
                .padding()
            }
            .background(VpnTheme.bgDark.ignoresSafeArea())
            .navigationTitle("GPTGuard")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var heroCard: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle().fill(statusBg).frame(width: 68, height: 68)
                switch engine.snapshot.status {
                case .startingCore, .verifyingExit:
                    ProgressView().tint(VpnTheme.warnAmber).scaleEffect(1.3)
                case .blackholeKillSwitch:
                    Image(systemName: "exclamationmark.shield.fill").font(.system(size: 34)).foregroundStyle(VpnTheme.killRed)
                case .protected:
                    Image(systemName: "checkmark.shield.fill").font(.system(size: 34)).foregroundStyle(VpnTheme.shieldGreen)
                case .stopped:
                    Image(systemName: "lock.shield").font(.system(size: 32)).foregroundStyle(VpnTheme.textSecondary)
                }
            }

            Text(titleText)
                .font(.title3.bold())
                .foregroundStyle(statusColor)

            Text(subtitleText)
                .font(.caption)
                .foregroundStyle(VpnTheme.textSecondary)
                .multilineTextAlignment(.center)

            if let err = engine.lastDisconnectError, !err.isEmpty, engine.snapshot.status == .stopped {
                Text(err)
                    .font(.caption2)
                    .foregroundStyle(VpnTheme.killRed)
                    .multilineTextAlignment(.center)
                    .padding(10)
                    .frame(maxWidth: .infinity)
                    .background(VpnTheme.killRedBg)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }

            if engine.snapshot.status == .protected {
                Button {
                    openOfficialChatGPT()
                } label: {
                    Label("安全启动官方 ChatGPT iOS 客户端", systemImage: "arrow.up.right.square.fill")
                        .font(.subheadline.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(VpnTheme.shieldGreen)
                        .foregroundStyle(VpnTheme.bgDark)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }

                HStack(spacing: 10) {
                    Button { engine.tripBlackholeKillSwitch() } label: {
                        Label("黑洞熔断", systemImage: "power")
                            .font(.caption.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(VpnTheme.killRedBg)
                            .foregroundStyle(VpnTheme.killRed)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    Button { engine.stopVpnCompletely() } label: {
                        Label("关闭 VPN", systemImage: "stop.fill")
                            .font(.caption.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(VpnTheme.cardDark)
                            .foregroundStyle(VpnTheme.textSecondary)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                }
            } else if engine.snapshot.status == .blackholeKillSwitch {
                Button { engine.reverifyAndRecover() } label: {
                    Label("重新校验出口并恢复官方 ChatGPT 网络", systemImage: "arrow.clockwise")
                        .font(.subheadline.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(VpnTheme.accentTeal)
                        .foregroundStyle(VpnTheme.bgDark)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                HStack(spacing: 10) {
                    Button("切换身份/节点") { selectedTab = 2 }
                        .font(.caption.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(VpnTheme.cardDark)
                        .foregroundStyle(VpnTheme.textPrimary)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    Button("关闭 VPN") { engine.stopVpnCompletely() }
                        .font(.caption.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(VpnTheme.cardDark)
                        .foregroundStyle(VpnTheme.textSecondary)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
            } else if engine.snapshot.status == .stopped {
                if let sess = engine.activeSession ?? engine.sessions.first {
                    Button {
                        engine.startProtection(forSessionId: sess.id)
                    } label: {
                        Label("开启隔离守护 (\(sess.name))", systemImage: "play.fill")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTeal)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                } else if let firstNode = engine.nodes.first {
                    Button {
                        engine.connectNodeShortcut(firstNode.id)
                    } label: {
                        Label("开启隔离守护 (\(firstNode.name))", systemImage: "play.fill")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTeal)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                } else {
                    Button {
                        selectedTab = 3
                    } label: {
                        Label("先去导入机场订阅 / 代理节点", systemImage: "icloud.and.arrow.down")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTerracotta)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            } else {
                Button("取消并关闭") { engine.stopVpnCompletely() }
                    .font(.caption)
                    .foregroundStyle(VpnTheme.textSecondary)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(statusColor.opacity(0.5), lineWidth: 1.4))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    private var modeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("iOS 官方客户端隔离模式").font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary)

            Toggle(isOn: Binding(
                get: { engine.settings.globalMode },
                set: { v in engine.updateSettings { $0.globalMode = v } }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("全局模式（默认关闭：仅接管 ChatGPT / OpenAI 域名）").font(.caption.bold()).foregroundStyle(VpnTheme.textPrimary)
                    Text("关闭时只有 ChatGPT 相关流量走代理、其他 App 直连；开启时整机流量走代理，熔断时整机黑洞。")
                        .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
            }
            .tint(VpnTheme.accentTeal)

            Toggle(isOn: Binding(
                get: { engine.settings.includeAuthHelperDomains },
                set: { v in engine.updateSettings { $0.includeAuthHelperDomains = v } }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("包含 Google / Apple 登录验证域名").font(.caption.bold()).foregroundStyle(VpnTheme.textPrimary)
                    Text("在官方 ChatGPT iOS 客户端使用 Google 或 Apple ID 登录时建议保持开启。")
                        .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
            }
            .tint(VpnTheme.accentTeal)
        }
        .padding(16)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(VpnTheme.borderDark, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private var architectureNoteCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("iOS 黑洞防直连机制说明").font(.caption.bold()).foregroundStyle(VpnTheme.accentTeal)
            Text("隧道启动时先把 ChatGPT 流量封进黑洞，出口经代理校验通过后才放行，任何情况下都不会回落直连。巡检失败、网络切换会立即封锁并自动重试；若代理出口 IP 与本机直连 IP 相同（节点没生效），也会立即掐断。手动熔断、地区或锁定 IP 不符时，需要手动重新校验。")
                .font(.caption2)
                .foregroundStyle(VpnTheme.textSecondary)
                .lineSpacing(3)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VpnTheme.cardDark)
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var diagnosticsCard: some View {
        Button { selectedTab = 1 } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Label("降智 / 纯净度 / 时区", systemImage: "stethoscope")
                        .font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary)
                    Spacer()
                    Text(diagnostics.verdict.title).font(.caption.bold()).foregroundStyle(diagnostics.verdict.color)
                    Image(systemName: "chevron.right").font(.caption).foregroundStyle(VpnTheme.textSecondary)
                }
                HStack(spacing: 8) {
                    pill(purityText, color: purityColor)
                    pill(diagnostics.latestPow.map { "PoW \($0.risk.title)" } ?? "PoW 未测",
                         color: diagnostics.latestPow?.risk.color ?? VpnTheme.textSecondary)
                    pill(timezoneText, color: timezoneColor)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(VpnTheme.surfaceDark)
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(VpnTheme.borderDark, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
    }

    private var purityText: String {
        guard let report = diagnostics.report else { return "纯净度 —" }
        return "纯净度 \(report.score)"
    }

    private var purityColor: Color {
        guard let report = diagnostics.report else { return VpnTheme.textSecondary }
        switch report.grade {
        case .clean: return VpnTheme.shieldGreen
        case .fair: return Color.yellow
        case .poor: return VpnTheme.warnAmber
        case .risky: return VpnTheme.killRed
        }
    }

    private var timezoneText: String {
        guard let status = diagnostics.timezone?.status else { return "时区 —" }
        switch status {
        case .match, .sameOffset: return "时区吻合"
        case .mismatch: return "时区不吻合"
        case .unknown: return "时区未知"
        }
    }

    private var timezoneColor: Color {
        guard let status = diagnostics.timezone?.status else { return VpnTheme.textSecondary }
        switch status {
        case .match: return VpnTheme.shieldGreen
        case .sameOffset: return Color.yellow
        case .mismatch: return VpnTheme.killRed
        case .unknown: return VpnTheme.textSecondary
        }
    }

    private func pill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .lineLimit(1)
            .padding(.horizontal, 8).padding(.vertical, 4)
            .foregroundStyle(color)
            .background(color.opacity(0.15))
            .clipShape(Capsule())
    }

    /// Opens the official ChatGPT app (custom scheme first, then the universal link / Safari).
    private func openOfficialChatGPT() {
        guard let scheme = URL(string: "chatgpt://"), let web = URL(string: "https://chatgpt.com/") else { return }
        UIApplication.shared.open(scheme, options: [:]) { opened in
            if !opened { UIApplication.shared.open(web) }
        }
    }

    private var titleText: String {
        switch engine.snapshot.status {
        case .protected: return "官方 ChatGPT 已隔离保护"
        case .blackholeKillSwitch: return "黑洞熔断已生效（零直连泄露）"
        case .startingCore: return "黑洞锁定中 · 启动内核..."
        case .verifyingExit: return "黑洞锁定中 · 校验出口..."
        case .stopped: return "官方客户端隔离未开启"
        }
    }

    private var subtitleText: String {
        switch engine.snapshot.status {
        case .protected:
            let sess = engine.snapshot.activeSessionName.map { "身份: \($0)\n" } ?? ""
            let loc = [engine.snapshot.exitCountry, engine.snapshot.exitIp, engine.snapshot.exitCity].compactMap { $0 }.joined(separator: " · ")
            return "\(sess)出口 \(loc) (\(engine.snapshot.latencyMs ?? 0)ms)\n后台每 \(engine.settings.watchdogIntervalSec) 秒持续防封巡检中"
        case .blackholeKillSwitch:
            return engine.snapshot.killSwitchReason ?? "ChatGPT 流量已被黑洞拦截，零直连泄露"
        case .startingCore, .verifyingExit:
            return "正在黑洞保护下校验海外出口，通过后自动放行"
        case .stopped:
            return "开启后通过系统 PacketTunnel 接管官方 ChatGPT 客户端流量，只允许走代理，检测到直连立即黑洞掐断"
        }
    }
}
