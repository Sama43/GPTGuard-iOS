import SwiftUI

struct SessionsView: View {
    @ObservedObject var engine: VpnManagerEngine
    @Binding var selectedTab: Int

    @State private var showCreate = false
    @State private var rebindTarget: AppIdentitySession? = nil
    @State private var switchConfirmTarget: AppIdentitySession? = nil
    @State private var deleteTarget: AppIdentitySession? = nil

    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                Text("iOS 沙盒说明：每个身份严格绑定独立节点与出口 IP 锁。切换不同官方客户端身份时，会先触发黑洞断网，请先在官方 ChatGPT App 中退出旧账号后再激活新身份以防串号。")
                    .font(.caption2)
                    .foregroundStyle(VpnTheme.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(VpnTheme.cardDark)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .padding(.horizontal)

                if engine.nodes.isEmpty {
                    Spacer()
                    Button("前往导入节点") { selectedTab = 3 }
                        .buttonStyle(.borderedProminent)
                        .tint(VpnTheme.accentTeal)
                    Spacer()
                } else if engine.sessions.isEmpty {
                    Spacer()
                    Button("创建第一个官方客户端身份") { showCreate = true }
                        .buttonStyle(.borderedProminent)
                        .tint(VpnTheme.accentTeal)
                    Spacer()
                } else {
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            ForEach(engine.sessions) { sess in
                                card(sess)
                            }
                        }
                        .padding(.horizontal)
                        .padding(.bottom, 16)
                    }
                }
            }
            .background(VpnTheme.bgDark.ignoresSafeArea())
            .navigationTitle("官方客户端身份会话")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showCreate = true } label: { Image(systemName: "plus") }
                        .disabled(engine.nodes.isEmpty)
                        .tint(VpnTheme.accentTeal)
                }
            }
            .sheet(isPresented: $showCreate) {
                CreateAppSessionSheet(nodes: engine.nodes) { name, hint, nid in
                    let created = engine.createSession(name: name, accountHint: hint, boundNodeId: nid)
                    showCreate = false
                    engine.startProtection(forSessionId: created.id)
                    selectedTab = 0
                }
            }
            .sheet(item: $rebindTarget) { sess in
                RebindAppNodeSheet(session: sess, nodes: engine.nodes) { nid in
                    engine.rebindSessionNode(sessionId: sess.id, newNodeId: nid)
                    rebindTarget = nil
                }
            }
            .alert("防串号安全切号确认", isPresented: Binding(
                get: { switchConfirmTarget != nil },
                set: { if !$0 { switchConfirmTarget = nil } }
            )) {
                Button("保持黑洞", role: .cancel) { switchConfirmTarget = nil }
                Button("已退出旧号，激活新身份") {
                    if let t = switchConfirmTarget {
                        engine.startProtection(forSessionId: t.id)
                        selectedTab = 0
                    }
                    switchConfirmTarget = nil
                }
            } message: {
                Text("已将官方 ChatGPT 切入黑洞断网防止旧 Token 走新 IP。请确认已在官方 ChatGPT 中退出旧账号后再激活「\(switchConfirmTarget?.name ?? "")」。")
            }
            .alert("删除身份会话？", isPresented: Binding(
                get: { deleteTarget != nil },
                set: { if !$0 { deleteTarget = nil } }
            )) {
                Button("取消", role: .cancel) { deleteTarget = nil }
                Button("删除", role: .destructive) {
                    if let t = deleteTarget { engine.deleteSession(t.id) }
                    deleteTarget = nil
                }
            } message: {
                Text("删除「\(deleteTarget?.name ?? "")」后，若当前正在运行将自动保持黑洞封锁以防直连。")
            }
        }
    }

    private func card(_ sess: AppIdentitySession) -> some View {
        let bound = engine.nodes.first { $0.id == sess.boundNodeId }
        let isActive = engine.activeSessionId == sess.id
        let isProtected = isActive && engine.snapshot.status == .protected
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "person.badge.shield.checkmark.fill")
                    .foregroundStyle(isProtected ? VpnTheme.shieldGreen : VpnTheme.accentTeal)
                VStack(alignment: .leading, spacing: 2) {
                    Text(sess.name).font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary)
                    if !sess.accountHint.isEmpty {
                        Text("单账号备忘: \(sess.accountHint)").font(.caption2).foregroundStyle(VpnTheme.accentTeal)
                    }
                }
                Spacer()
                if isProtected { Image(systemName: "checkmark.circle.fill").foregroundStyle(VpnTheme.shieldGreen) }
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(bound.map { "绑定节点: [\($0.protocol.label)] \($0.name)" } ?? "绑定节点已删除")
                    .font(.caption).foregroundStyle(bound != nil ? VpnTheme.textPrimary : VpnTheme.killRed).lineLimit(1)
                if sess.lockExitIp, let ip = sess.pinnedExitIp {
                    Text("🔒 锁定出口 IP: \(ip)\(sess.pinnedExitIpAlt.map { " / \($0)" } ?? "")").font(.caption2).foregroundStyle(VpnTheme.shieldGreen)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(VpnTheme.cardDark)
            .clipShape(RoundedRectangle(cornerRadius: 8))

            HStack(spacing: 8) {
                Button {
                    if engine.activeSessionId != nil && engine.activeSessionId != sess.id && engine.snapshot.status == .protected {
                        engine.tripBlackholeKillSwitch()
                        switchConfirmTarget = sess
                    } else {
                        engine.startProtection(forSessionId: sess.id)
                        selectedTab = 0
                    }
                } label: {
                    Text(isProtected ? "守护中" : "激活此身份")
                        .font(.caption.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 7)
                        .background(isProtected ? VpnTheme.shieldGreen : VpnTheme.accentTeal)
                        .foregroundStyle(VpnTheme.bgDark)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .disabled(bound == nil)

                Button { rebindTarget = sess } label: {
                    Image(systemName: "arrow.left.arrow.right")
                        .frame(width: 32, height: 32).background(VpnTheme.cardDark).foregroundStyle(VpnTheme.textPrimary).clipShape(RoundedRectangle(cornerRadius: 8))
                }
                if sess.lockExitIp, sess.pinnedExitIp != nil {
                    Button { engine.clearSessionExitIp(sessionId: sess.id) } label: {
                        Image(systemName: "lock.open.fill")
                            .frame(width: 32, height: 32).background(VpnTheme.cardDark).foregroundStyle(VpnTheme.warnAmber).clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                } else if isProtected, let ip = engine.snapshot.exitIp {
                    Button { engine.pinSessionExitIp(sessionId: sess.id, ip: ip) } label: {
                        Image(systemName: "lock.fill")
                            .frame(width: 32, height: 32).background(VpnTheme.cardDark).foregroundStyle(VpnTheme.shieldGreen).clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                Button { deleteTarget = sess } label: {
                    Image(systemName: "trash.fill")
                        .frame(width: 32, height: 32).background(VpnTheme.killRedBg).foregroundStyle(VpnTheme.killRed).clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
        }
        .padding(12)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(isProtected ? VpnTheme.shieldGreen.opacity(0.7) : VpnTheme.borderDark, lineWidth: 1.2))
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

private struct CreateAppSessionSheet: View {
    let nodes: [ProxyNode]
    let onCreate: (String, String, UUID) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var hint = ""
    @State private var query = ""
    @State private var selectedNodeId: UUID?

    private var filtered: [ProxyNode] {
        query.isEmpty ? nodes : nodes.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("身份信息") {
                    TextField("身份名称（如：官方主力号）", text: $name)
                    TextField("单账号备忘（可选）", text: $hint)
                }
                Section("绑定专属节点") {
                    TextField("搜索节点", text: $query)
                    ForEach(filtered) { n in
                        Button { selectedNodeId = n.id } label: {
                            HStack {
                                Text("\(n.name) (\(n.protocol.label))").foregroundStyle(VpnTheme.textPrimary)
                                Spacer()
                                if selectedNodeId == n.id { Image(systemName: "checkmark.circle.fill").foregroundStyle(VpnTheme.accentTeal) }
                            }
                        }
                    }
                }
            }
            .navigationTitle("新建官方客户端身份")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("创建并启动") {
                        if let nid = selectedNodeId ?? nodes.first?.id { onCreate(name, hint, nid) }
                    }
                }
            }
            .onAppear { selectedNodeId = nodes.first?.id }
        }
    }
}

private struct RebindAppNodeSheet: View {
    let session: AppIdentitySession
    let nodes: [ProxyNode]
    let onSelect: (UUID) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    private var filtered: [ProxyNode] {
        query.isEmpty ? nodes : nodes.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        NavigationStack {
            List {
                TextField("搜索节点", text: $query)
                ForEach(filtered) { n in
                    Button { onSelect(n.id) } label: {
                        HStack {
                            Text("\(n.name) (\(n.protocol.label))").foregroundStyle(VpnTheme.textPrimary)
                            Spacer()
                            if session.boundNodeId == n.id { Image(systemName: "checkmark").foregroundStyle(VpnTheme.accentTeal) }
                        }
                    }
                }
            }
            .navigationTitle("更换绑定节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } } }
        }
    }
}
