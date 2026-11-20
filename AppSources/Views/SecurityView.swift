import SwiftUI
import UIKit

struct SecurityView: View {
    @ObservedObject var engine: VpnManagerEngine
    @State private var showRegions = false
    @State private var logTab = 0

    var body: some View {
        NavigationStack {
            List {
                Section("PacketTunnel 隔离状态") {
                    row("系统 VPN 状态", engine.vpnStatusText, engine.vpnStatus == .connected)
                    row("扩展 Bundle ID", engine.resolvedExtensionId, true)
                    row("配置通道", engine.appGroupAvailable ? "App Group + 环回鉴权控制" : "环回鉴权直传（兼容重签）", true)
                    row("隧道模式", engine.settings.globalMode ? "全局代理 + 全局黑洞" : "仅接管 ChatGPT / OpenAI 域名（其他直连）", true)
                    row("DNS 防泄露", "TUN 172.19.0.1 + FakeIP 198.18.0.0/15 + DoH", true)
                    row("当前出口", [engine.snapshot.exitCountry, engine.snapshot.exitIp, engine.snapshot.exitCity].compactMap { $0 }.joined(separator: " · ").nonEmpty ?? "未校验", engine.snapshot.exitIp != nil)
                    if engine.settings.detectDirectLeak {
                        row("本机直连 IP", engine.snapshot.directIp ?? "探测中 / 未连接", engine.snapshot.directIp != nil)
                    }

                    if let err = engine.lastDisconnectError, !err.isEmpty {
                        Text("最近异常: \(err)")
                            .font(.caption2)
                            .foregroundStyle(VpnTheme.killRed)
                    }

                    if engine.settings.lockExitIp, let pinned = engine.settings.pinnedExitIp {
                        Button("解除全局锁 IP (\(pinned))") { engine.clearGlobalExitIp() }
                            .foregroundStyle(VpnTheme.warnAmber)
                    } else {
                        Button("锁定当前出口 IP（漂移瞬间黑洞熔断）") { engine.pinGlobalExitIp() }
                            .disabled(engine.snapshot.exitIp == nil)
                            .foregroundStyle(VpnTheme.accentTeal)
                    }
                }

                Section("防封熔断策略") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("后台出口巡检频率（异常自动黑洞）").font(.subheadline)
                        Picker("巡检频率", selection: Binding(
                            get: { engine.settings.watchdogIntervalSec },
                            set: { v in engine.updateSettings { $0.watchdogIntervalSec = v } }
                        )) {
                            Text("3秒").tag(3)
                            Text("5秒").tag(5)
                            Text("10秒").tag(10)
                            Text("20秒").tag(20)
                        }.pickerStyle(.segmented)
                    }

                    Button { showRegions = true } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("出口地区熔断规则").foregroundStyle(VpnTheme.textPrimary)
                            Text("禁止: \(engine.settings.blockedCountries.sorted().joined(separator: ","))")
                                .font(.caption2).foregroundStyle(VpnTheme.killRed)
                            if !engine.settings.allowedCountries.isEmpty {
                                Text("仅允许: \(engine.settings.allowedCountries.sorted().joined(separator: ","))")
                                    .font(.caption2).foregroundStyle(VpnTheme.shieldGreen)
                            }
                        }
                    }

                    Toggle("Wi-Fi/5G 切换瞬时黑洞重检", isOn: Binding(
                        get: { engine.settings.killOnNetworkChange },
                        set: { v in engine.updateSettings { $0.killOnNetworkChange = v } }
                    ))

                    Toggle(isOn: Binding(
                        get: { engine.settings.detectDirectLeak },
                        set: { v in engine.updateSettings { $0.detectDirectLeak = v } }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("直连泄露检测")
                            Text("出口 IP 与本机直连 IP 相同（节点没生效）时立即黑洞掐断 ChatGPT")
                                .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                        }
                    }

                    Toggle(isOn: Binding(
                        get: { engine.settings.onDemandReconnect },
                        set: { v in engine.updateSettings { $0.onDemandReconnect = v } }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("VPN 断开自动重连（按需连接）")
                            Text("隧道崩溃或重启手机后由系统自动拉起，避免 ChatGPT 在无保护时直连。下次开启守护时生效。")
                                .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                        }
                    }
                }

                Section {
                    Picker("日志", selection: $logTab) {
                        Text("安全事件 (\(engine.combinedEvents.count))").tag(0)
                        Text("sing-box 内核 (\(engine.snapshot.coreLogs.count))").tag(1)
                    }.pickerStyle(.segmented)

                    if logTab == 0 {
                        ForEach(engine.combinedEvents.prefix(40)) { ev in
                            Text("\(Self.ts(ev.timestamp)) [\(ev.tag)] \(ev.message)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(colorFor(ev.level))
                        }
                    } else {
                        ForEach(Array(engine.snapshot.coreLogs.suffix(40).reversed().enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(size: 10, design: .monospaced)).foregroundStyle(VpnTheme.textSecondary)
                        }
                    }
                } header: {
                    HStack {
                        Text("实时安全审计日志")
                        Spacer()
                        Button("复制") {
                            let text = engine.combinedEvents.map { "[\(Self.ts($0.timestamp))][\($0.tag)] \($0.message)" }.joined(separator: "\n")
                            UIPasteboard.general.string = text
                        }.font(.caption)
                        Button("清空") { engine.clearLogs() }.font(.caption).foregroundStyle(VpnTheme.killRed)
                    }
                }
            }
            .navigationTitle("隔离审计")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { engine.reverifyAndRecover() } label: { Image(systemName: "arrow.clockwise") }.tint(VpnTheme.accentTeal)
                }
            }
            .sheet(isPresented: $showRegions) {
                VpnRegionsSheet(settings: engine.settings) { b, a in
                    engine.updateSettings { $0.blockedCountries = b; $0.allowedCountries = a }
                    showRegions = false
                }
            }
        }
    }

    private func row(_ k: String, _ v: String, _ ok: Bool) -> some View {
        HStack {
            Text(k).font(.caption).foregroundStyle(VpnTheme.textSecondary)
            Spacer()
            Text(v).font(.caption2.bold()).foregroundStyle(ok ? VpnTheme.shieldGreen : VpnTheme.warnAmber)
        }
    }

    private func colorFor(_ level: EventLevel) -> Color {
        switch level {
        case .success: return VpnTheme.shieldGreen
        case .warn: return VpnTheme.warnAmber
        case .critical: return VpnTheme.killRed
        case .info: return VpnTheme.textSecondary
        }
    }

    private static func ts(_ d: Date) -> String {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f.string(from: d)
    }
}

private struct VpnRegionsSheet: View {
    let settings: VpnGuardSettings
    let onSave: (Set<String>, Set<String>) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var blocked = ""
    @State private var allowed = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("禁止地区代码 (逗号分隔)") { TextField("CN,HK,MO,RU,BY,KP,IR,SY,CU", text: $blocked).textInputAutocapitalization(.characters) }
                Section("仅允许白名单地区 (留空不限制)") { TextField("US,JP,SG,TW", text: $allowed).textInputAutocapitalization(.characters) }
            }
            .navigationTitle("出口地区熔断规则")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        let b = Set(blocked.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "，" }).map { $0.trimmingCharacters(in: .whitespaces).uppercased() }.filter { $0.count == 2 })
                        let a = Set(allowed.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "，" }).map { $0.trimmingCharacters(in: .whitespaces).uppercased() }.filter { $0.count == 2 })
                        onSave(b, a)
                    }
                }
            }
            .onAppear {
                blocked = settings.blockedCountries.sorted().joined(separator: ",")
                allowed = settings.allowedCountries.sorted().joined(separator: ",")
            }
        }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
