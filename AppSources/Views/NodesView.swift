import SwiftUI
import UIKit

private let vpnRiskyKeywords = [
    "香港", "hong kong", "hongkong", "🇭🇰", " hk", "hk ", "hk-", "-hk", "hk_", "hk0", "hk1",
    "澳门", "macau", "🇲🇴", "中国", "回国", "大陆", "俄罗斯", "russia", "🇷🇺",
    "剩余流量", "套餐到期", "过期时间", "官网", "失联", "重置", "续费", "公告"
]

private func isVpnRiskyName(_ name: String) -> Bool {
    let low = name.lowercased()
    return vpnRiskyKeywords.contains { low.contains($0) }
}

struct NodesView: View {
    @ObservedObject var engine: VpnManagerEngine
    @Binding var selectedTab: Int

    @State private var showImport = false
    @State private var importTab = 0
    @State private var prefillUrl = ""
    @State private var searchQuery = ""
    @State private var hideRisky = true
    @State private var subFilter: UUID? = nil
    @State private var banner: (Bool, String)? = nil
    @State private var testingIds: Set<UUID> = []
    @State private var passthroughPrompt: PassthroughPrompt? = nil
    @State private var refreshingSubs: Set<UUID> = []

    private var filtered: [ProxyNode] {
        engine.nodes.filter { n in
            let ms = subFilter == nil || n.subscriptionId == subFilter
            let mr = !hideRisky || !isVpnRiskyName(n.name)
            let mq = searchQuery.isEmpty || n.name.localizedCaseInsensitiveContains(searchQuery) || n.server.localizedCaseInsensitiveContains(searchQuery)
            return ms && mr && mq
        }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                HStack(spacing: 8) {
                    Button {
                        importTab = 0; prefillUrl = ""; showImport = true
                    } label: {
                        Label("添加机场订阅", systemImage: "icloud.and.arrow.down")
                            .font(.caption.bold()).frame(maxWidth: .infinity).padding(.vertical, 9)
                            .background(VpnTheme.accentTeal).foregroundStyle(VpnTheme.bgDark).clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    Button {
                        let text = (UIPasteboard.general.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                        if text.isEmpty { banner = (false, "剪贴板为空") }
                        else if text.lowercased().hasPrefix("https://") && !text.contains("\n") {
                            importTab = 0; prefillUrl = text; showImport = true
                        } else if text.lowercased().hasPrefix("http://") && !text.contains("\n") {
                            banner = (false, "仅支持 HTTPS 机场订阅链接，请将链接改为 https://")
                        } else {
                            let res = engine.importNodesFromText(text)
                            banner = res.nodes.isEmpty ? (false, res.errors.first ?? "无法识别") : (true, "成功导入 \(res.nodes.count) 个节点")
                        }
                    } label: {
                        Label("剪贴板导入", systemImage: "doc.on.clipboard")
                            .font(.caption.bold()).frame(maxWidth: .infinity).padding(.vertical, 9)
                            .background(VpnTheme.cardDark).foregroundStyle(VpnTheme.textPrimary).clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                }
                .padding(.horizontal)

                if let error = engine.catalogError {
                    HStack(spacing: 8) {
                        Text(error).foregroundStyle(VpnTheme.killRed).font(.caption)
                        Spacer()
                        Button("重建凭据库") { engine.resetCatalogAfterError() }
                            .font(.caption2.bold())
                            .padding(.horizontal, 8).padding(.vertical, 5)
                            .background(VpnTheme.killRedBg).foregroundStyle(VpnTheme.killRed)
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                    .padding(.horizontal)
                }
                if let b = banner {
                    Text(b.1).font(.caption).foregroundStyle(b.0 ? VpnTheme.shieldGreen : VpnTheme.killRed)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        .background(b.0 ? VpnTheme.shieldGreenBg : VpnTheme.killRedBg).clipShape(RoundedRectangle(cornerRadius: 8))
                        .padding(.horizontal)
                }

                ScrollView {
                    LazyVStack(spacing: 10) {
                        ForEach(engine.subscriptions) { sub in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(sub.name) (\(sub.nodeCount)节点)").font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary)
                                    if let total = sub.totalBytes, total > 0 {
                                        let used = (Double(sub.uploadBytes ?? 0) + Double(sub.downloadBytes ?? 0)) / 1_073_741_824.0
                                        Text(String(format: "已用 %.1fGB / %.1fGB", used, Double(total) / 1_073_741_824.0))
                                            .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                                    }
                                }
                                Spacer()
                                Button {
                                    refreshingSubs.insert(sub.id)
                                    Task {
                                        do {
                                            let (u, c) = try await engine.refreshSubscription(sub.id)
                                            banner = (true, "「\(u.name)」已更新 \(c) 个节点")
                                        } catch {
                                            banner = (false, error.localizedDescription)
                                        }
                                        refreshingSubs.remove(sub.id)
                                    }
                                } label: {
                                    if refreshingSubs.contains(sub.id) { ProgressView().scaleEffect(0.8) }
                                    else { Image(systemName: "arrow.clockwise").foregroundStyle(VpnTheme.shieldGreen) }
                                }
                                .disabled(refreshingSubs.contains(sub.id))
                                Button { engine.deleteSubscription(sub.id) } label: {
                                    Image(systemName: "trash").foregroundStyle(VpnTheme.textSecondary)
                                }.padding(.leading, 8)
                            }
                            .padding(12).background(VpnTheme.cardDark).clipShape(RoundedRectangle(cornerRadius: 12))
                        }

                        if !engine.nodes.isEmpty {
                            TextField("搜索节点（台湾/美国/日本/新加坡）", text: $searchQuery)
                                .padding(9).background(VpnTheme.surfaceDark).clipShape(RoundedRectangle(cornerRadius: 10))
                            ScrollView(.horizontal, showsIndicators: false) {
                                HStack(spacing: 8) {
                                    chip(hideRisky ? "已隐藏香港/提示" : "显示全部", active: hideRisky) { hideRisky.toggle() }
                                    chip("全部 (\(engine.nodes.count))", active: subFilter == nil) { subFilter = nil }
                                    ForEach(engine.subscriptions) { s in
                                        chip("\(s.name) (\(s.nodeCount))", active: subFilter == s.id) { subFilter = s.id }
                                    }
                                }
                            }
                        }

                        ForEach(filtered) { node in
                            let testing = testingIds.contains(node.id)
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(node.protocol.label).font(.caption2.bold()).padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(VpnTheme.accentTealBg).foregroundStyle(VpnTheme.accentTeal).clipShape(RoundedRectangle(cornerRadius: 5))
                                    Text(node.name).font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary).lineLimit(1)
                                    Spacer()
                                }
                                Text("\(node.server):\(node.port)").font(.caption2).foregroundStyle(VpnTheme.textSecondary).lineLimit(1)
                                if node.skipsTLSVerification { Text("此节点已关闭 TLS 证书验证").font(.caption2).foregroundStyle(VpnTheme.killRed) }
                                if node.usesDomainPassthrough {
                                    Text("域名直通：出口可能为 IPv6（长按卡片可关闭）").font(.caption2).foregroundStyle(VpnTheme.warnAmber)
                                }
                                if let cc = node.lastExitCountry {
                                    Text("出口: \(cc) · \(node.lastExitIp ?? "") · \(node.lastLatencyMs ?? 0)ms").font(.caption2).foregroundStyle(VpnTheme.shieldGreen)
                                }
                                HStack(spacing: 8) {
                                    Button {
                                        engine.connectNodeShortcut(node.id)
                                        selectedTab = 0
                                    } label: {
                                        Text("以此节点隔离官方 ChatGPT")
                                            .font(.caption.bold()).frame(maxWidth: .infinity).padding(.vertical, 7)
                                            .background(VpnTheme.accentTeal).foregroundStyle(VpnTheme.bgDark).clipShape(RoundedRectangle(cornerRadius: 8))
                                    }
                                    Button {
                                        testingIds.insert(node.id)
                                        Task {
                                            let res = await engine.testNodeIsolated(node)
                                            if res.needsDomainPassthrough {
                                                banner = (false, "\(node.name) 强制 IPv4 失败（节点拦截了 DNS 查询），域名直通可用")
                                                passthroughPrompt = PassthroughPrompt(nodeId: node.id, nodeName: node.name,
                                                    exit: "\(res.countryCode ?? "?") (\(res.exitIp ?? "-")) \(res.latencyMs ?? 0)ms")
                                            } else {
                                                banner = res.success
                                                    ? (true, "\(node.name): \(res.countryCode ?? "?") (\(res.exitIp ?? "-")) \(res.latencyMs ?? 0)ms")
                                                    : (false, "\(node.name) 测速失败: \(res.error ?? "")")
                                            }
                                            testingIds.remove(node.id)
                                        }
                                    } label: {
                                        if testing { ProgressView().scaleEffect(0.75).frame(width: 44, height: 30) }
                                        else {
                                            Text("测速").font(.caption.bold()).padding(.horizontal, 10).padding(.vertical, 7)
                                                .background(VpnTheme.cardDark).foregroundStyle(VpnTheme.textPrimary).clipShape(RoundedRectangle(cornerRadius: 8))
                                        }
                                    }.disabled(testing)
                                    Button { engine.deleteNode(node.id) } label: {
                                        Image(systemName: "trash").frame(width: 30, height: 30).foregroundStyle(VpnTheme.textSecondary)
                                    }
                                }
                            }
                            .padding(12).background(VpnTheme.surfaceDark)
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(VpnTheme.borderDark, lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                            .contextMenu {
                                Button {
                                    engine.setDomainPassthrough(node.id, enabled: !node.usesDomainPassthrough)
                                } label: {
                                    Label(node.usesDomainPassthrough ? "关闭域名直通（恢复强制 IPv4）" : "开启域名直通（允许 IPv6 出口）",
                                          systemImage: "arrow.triangle.branch")
                                }
                            }
                        }
                    }
                    .padding(.horizontal).padding(.bottom, 16)
                }
            }
            .background(VpnTheme.bgDark.ignoresSafeArea())
            .alert("该节点拦截了 DNS 查询", isPresented: Binding(
                get: { passthroughPrompt != nil },
                set: { if !$0 { passthroughPrompt = nil } }
            ), presenting: passthroughPrompt) { prompt in
                Button("开启域名直通") { engine.setDomainPassthrough(prompt.nodeId, enabled: true) }
                Button("暂不开启", role: .cancel) {}
            } message: { prompt in
                Text("「\(prompt.nodeName)」无法强制 IPv4 出口，但改用域名直通测速成功：\(prompt.exit)。\n开启后由节点决定走 IPv4 还是 IPv6，锁定 IP 时会同时记录这个节点的两种出口，不会因切换而误熔断。")
            }
            .navigationTitle("节点与机场订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { importTab = 1; showImport = true } label: { Image(systemName: "plus") }.tint(VpnTheme.accentTeal)
                }
            }
            .sheet(isPresented: $showImport) {
                VpnImportSheet(initialTab: importTab, prefillUrl: prefillUrl, engine: engine) { message in
                    banner = (true, message)
                    showImport = false
                }
            }
        }
    }

    private func chip(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.caption2.bold()).padding(.horizontal, 10).padding(.vertical, 6)
                .background(active ? VpnTheme.accentTealBg : VpnTheme.cardDark)
                .foregroundStyle(active ? VpnTheme.accentTeal : VpnTheme.textSecondary)
                .clipShape(Capsule())
        }
    }
}

private struct VpnImportSheet: View {
    let initialTab: Int
    let prefillUrl: String
    @ObservedObject var engine: VpnManagerEngine
    let onFinish: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var tab = 0
    @State private var allowDirect = true
    @State private var subName = ""
    @State private var subUrl = ""
    @State private var rawText = ""
    @State private var loading = false
    @State private var importError: String?

    var body: some View {
        NavigationStack {
            Form {
                Picker("导入方式", selection: $tab) {
                    Text("机场订阅").tag(0)
                    Text("链接 / YAML").tag(1)
                }.pickerStyle(.segmented)
                if tab == 0 {
                    Section("机场订阅 URL (Clash YAML / V2Ray Base64)") {
                        Toggle("未连接时允许直接下载订阅", isOn: $allowDirect)
                        TextField("订阅名称 (可选)", text: $subName)
                        TextField("https://...", text: $subUrl).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                } else {
                    Section("粘贴节点链接或 Clash YAML") {
                        TextEditor(text: $rawText).frame(minHeight: 160).font(.caption.monospaced())
                    }
                }
                if let importError {
                    Text(importError).foregroundStyle(VpnTheme.killRed)
                }
            }
            .interactiveDismissDisabled(loading)
            .navigationTitle("导入机场订阅 / 节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() }.disabled(loading) }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loading ? "拉取中..." : "导入") {
                        importError = nil
                        if tab == 0 {
                            loading = true
                            Task {
                                defer { loading = false }
                                do {
                                    let (s, c) = try await engine.addAndSyncSubscription(name: subName, url: subUrl, allowDirectBootstrap: allowDirect)
                                    onFinish("已导入订阅「\(s.name)」共 \(c) 个节点")
                                } catch {
                                    importError = error.localizedDescription
                                }
                            }
                        } else {
                            let res = engine.importNodesFromText(rawText)
                            if res.nodes.isEmpty {
                                importError = res.errors.first ?? "解析失败"
                            } else {
                                onFinish("成功导入 \(res.nodes.count) 个节点")
                            }
                        }
                    }.disabled(loading)
                }
            }
            .onAppear { tab = initialTab; subUrl = prefillUrl }
        }
    }
}

private struct PassthroughPrompt {
    let nodeId: UUID
    let nodeName: String
    let exit: String
}
