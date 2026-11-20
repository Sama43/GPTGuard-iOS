import SwiftUI

@main
struct GPTGuardApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var engine = VpnManagerEngine()
    @StateObject private var diagnostics = DiagnosticsStore()
    @State private var selectedTab = 0

    var body: some Scene {
        WindowGroup {
            TabView(selection: $selectedTab) {
                ShieldDashboardView(engine: engine, diagnostics: diagnostics, selectedTab: $selectedTab)
                    .tabItem { Label("守护", systemImage: "shield.checkered") }
                    .tag(0)

                DiagnosticsView(engine: engine, diagnostics: diagnostics)
                    .tabItem { Label("检测", systemImage: "stethoscope") }
                    .tag(1)

                SessionsView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("身份 (\(engine.sessions.count))", systemImage: "person.badge.shield.checkmark.fill") }
                    .tag(2)

                NodesView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("节点 (\(engine.nodes.count))", systemImage: "server.rack") }
                    .tag(3)

                SecurityView(engine: engine)
                    .tabItem { Label("审计", systemImage: "lock.doc.fill") }
                    .tag(4)
            }
            .onChange(of: scenePhase, initial: true) { _, phase in engine.setForeground(phase == .active) }
            // Re-check purity / timezone whenever the protected exit IP changes.
            .onChange(of: engine.snapshot.exitIp) { _, ip in
                if ip != nil, engine.snapshot.status == .protected { diagnostics.run() }
            }
            .alert("IP 时区与本机时区不吻合", isPresented: Binding(
                get: { diagnostics.timezoneAlert != nil },
                set: { if !$0 { diagnostics.timezoneAlert = nil } }
            )) {
                Button("查看详情") { selectedTab = 1; diagnostics.timezoneAlert = nil }
                Button("知道了", role: .cancel) { diagnostics.timezoneAlert = nil }
            } message: {
                if let tz = diagnostics.timezoneAlert {
                    Text("ChatGPT 看到的 IP 位于 \(tz.ipId ?? "?")（\(tz.ipOffsetSec.map(TimezoneCheck.formatOffset) ?? "?")），本机时区是 \(tz.deviceId)（\(TimezoneCheck.formatOffset(tz.deviceOffsetSec))）。部分服务会把这种不一致当作风险信号。")
                }
            }
            .tint(VpnTheme.accentTeal)
            .preferredColorScheme(.dark)
        }
    }
}
