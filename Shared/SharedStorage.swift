import Foundation
import CryptoKit

final class SharedStorage {
    private let defaults: UserDefaults
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init() {
        self.defaults = UserDefaults(suiteName: SharedConstants.appGroupId) ?? .standard
    }

    private enum Keys {
        static let catalog = "cag_ios_catalog_v2"
        static let nodes = "cag_ios_nodes_v1"
        static let subscriptions = "cag_ios_subs_v1"
        static let sessions = "cag_ios_sessions_v1"
        static let activeSessionId = "cag_ios_active_session_v1"
        static let settings = "cag_ios_settings_v1"
        static let snapshot = "cag_ios_tunnel_snapshot_v1"
    }

    func loadCatalog(migrate: Bool = false) throws -> CredentialCatalog {
        if let encrypted = defaults.data(forKey: Keys.catalog) {
            let sealed = try AES.GCM.SealedBox(combined: encrypted)
            let data = try AES.GCM.open(sealed, using: CatalogKey().load(create: false))
            let catalog = try decoder.decode(CredentialCatalog.self, from: data)
            if migrate { removeLegacyCatalog() }
            return catalog
        }
        let oldNodes = defaults.data(forKey: Keys.nodes)
        let oldSubscriptions = defaults.data(forKey: Keys.subscriptions)
        let catalog = CredentialCatalog(
            nodes: try oldNodes.map { try decoder.decode([ProxyNode].self, from: $0) } ?? [],
            subscriptions: try oldSubscriptions.map { try decoder.decode([SubscriptionProfile].self, from: $0) } ?? [])
        if migrate && (oldNodes != nil || oldSubscriptions != nil) { try saveCatalog(catalog) }
        return catalog
    }

    func saveCatalog(_ catalog: CredentialCatalog) throws {
        let key = try CatalogKey().load(create: defaults.data(forKey: Keys.catalog) == nil)
        let sealed = try AES.GCM.seal(encoder.encode(catalog), using: key)
        guard let combined = sealed.combined else { throw CocoaError(.fileWriteUnknown) }
        defaults.set(combined, forKey: Keys.catalog)
        removeLegacyCatalog()
    }

    /// Recovers from an unreadable catalog (e.g. after re-signing with a new Team ID that wiped Keychain).
    func resetCatalog() throws {
        defaults.removeObject(forKey: Keys.catalog)
        removeLegacyCatalog()
        CatalogKey().delete()
        try saveCatalog(CredentialCatalog(nodes: [], subscriptions: []))
    }

    private func removeLegacyCatalog() {
        for name in [Keys.nodes, Keys.subscriptions] where defaults.object(forKey: name) != nil {
            defaults.removeObject(forKey: name)
        }
    }

    func loadSessions() -> [AppIdentitySession] { load(Keys.sessions) ?? [] }
    func saveSessions(_ items: [AppIdentitySession]) { save(items, forKey: Keys.sessions) }

    func loadActiveSessionId() -> UUID? {
        defaults.string(forKey: Keys.activeSessionId).flatMap(UUID.init)
    }
    func saveActiveSessionId(_ id: UUID?) {
        defaults.set(id?.uuidString, forKey: Keys.activeSessionId)
    }

    func loadSettings() -> VpnGuardSettings { load(Keys.settings) ?? VpnGuardSettings() }
    func saveSettings(_ s: VpnGuardSettings) { save(s, forKey: Keys.settings) }

    func loadSnapshot() -> TunnelSnapshot { load(Keys.snapshot) ?? TunnelSnapshot() }
    func saveSnapshot(_ snap: TunnelSnapshot) {
        var stored = snap
        stored.coreLogs = []
        stored.probePort = nil
        save(stored, forKey: Keys.snapshot)
    }

    private func load<T: Decodable>(_ key: String) -> T? {
        guard let data = defaults.data(forKey: key) else { return nil }
        return try? decoder.decode(T.self, from: data)
    }

    private func save<T: Encodable>(_ value: T, forKey key: String) {
        if let data = try? encoder.encode(value) {
            defaults.set(data, forKey: key)
        }
    }
}
