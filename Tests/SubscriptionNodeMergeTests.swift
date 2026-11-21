import Foundation

@main
struct SubscriptionNodeMergeTests {
    static func main() {
        let subscriptionId = UUID()
        let outbound = #"{"type":"socks","tag":"proxy","server":"example.com","server_port":1080}"#
        let reordered = #"{"server_port":1080,"server":"example.com","tag":"proxy","type":"socks"}"#
        let rotated = #"{"type":"socks","tag":"proxy","server":"example.com","server_port":1080,"password":"new"}"#

        var primary = node("Primary", outbound: outbound)
        primary.createdAt = Date(timeIntervalSince1970: 100)
        primary.lastLatencyMs = 42
        primary.lastExitIp = "192.0.2.1"
        primary.lastExitCountry = "US"
        primary.lastExitOrg = "Example"
        primary.domainPassthrough = true
        let secondary = node("Secondary", outbound: outbound)
        let removed = node("Removed", outbound: #"{"type":"socks","server":"removed.example.com"}"#)
        let renamed = node("Renamed", outbound: reordered)
        let incoming = [renamed, node("Primary", outbound: reordered)]
        let updated = SubscriptionNodeMerge.merge(incoming, with: [primary, secondary, removed], subscriptionId: subscriptionId)

        precondition(updated.map(\.id) == [secondary.id, primary.id], "Match exact names before reconciling a rename")
        precondition(updated.map(\.name) == ["Renamed", "Primary"], "Keep subscription order and current names")
        precondition(updated.allSatisfy { $0.subscriptionId == subscriptionId }, "Tag every incoming node")
        precondition(updated[1].createdAt == primary.createdAt, "Keep original import time")
        precondition(updated[1].lastLatencyMs == 42, "Keep previous latency")
        precondition(updated[1].lastExitIp == primary.lastExitIp, "Keep previous IP")
        precondition(updated[1].lastExitCountry == primary.lastExitCountry, "Keep previous country")
        precondition(updated[1].lastExitOrg == primary.lastExitOrg, "Keep previous network")
        precondition(updated[1].usesDomainPassthrough, "Keep the domain-passthrough choice across refreshes")
        precondition(!updated[0].usesDomainPassthrough, "Domain passthrough stays off by default")

        let changed = node("Primary", outbound: rotated)
        let replacements = SubscriptionNodeMerge.merge([changed], with: [primary], subscriptionId: subscriptionId)
        precondition(replacements.map(\.id) == [changed.id], "Changed credentials must not inherit an existing binding")

        let ambiguous = [node("A", outbound: reordered), node("B", outbound: reordered)]
        let unmatched = SubscriptionNodeMerge.merge(ambiguous, with: [primary, secondary], subscriptionId: subscriptionId)
        precondition(unmatched.map(\.id) == ambiguous.map(\.id), "Ambiguous renames must not inherit bindings")

        let duplicate = node("Primary", outbound: outbound)
        let duplicateInput = [node("Primary", outbound: reordered), node("Primary", outbound: reordered)]
        let duplicates = SubscriptionNodeMerge.merge(duplicateInput, with: [primary, duplicate], subscriptionId: subscriptionId)
        precondition(duplicates.map(\.id) == [primary.id, duplicate.id], "Duplicate entries need distinct, stable IDs")

        let legacyNode = #"{"id":"6B1F2C3D-0000-4000-8000-000000000001","name":"Old","protocol":"VLESS","server":"h","port":443,"rawUri":"","singBoxOutboundJson":"{}","createdAt":0}"#
        let decodedNode = try! JSONDecoder().decode(ProxyNode.self, from: Data(legacyNode.utf8))
        precondition(!decodedNode.usesDomainPassthrough, "Catalogs saved before 1.0.6 still decode")
        let legacySettings = try! JSONEncoder().encode(VpnGuardSettings())
        var settingsObject = try! JSONSerialization.jsonObject(with: legacySettings) as! [String: Any]
        settingsObject.removeValue(forKey: "pinnedExitIpAlt")
        let settingsData = try! JSONSerialization.data(withJSONObject: settingsObject)
        precondition((try? JSONDecoder().decode(VpnGuardSettings.self, from: settingsData)) != nil, "Settings saved before 1.0.6 still decode")

        print("Subscription node merge regression tests passed")
    }

    private static func node(_ name: String, outbound: String) -> ProxyNode {
        ProxyNode(name: name, protocol: .socks5, server: "example.com", port: 1080, singBoxOutboundJson: outbound)
    }
}
