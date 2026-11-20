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

        print("Subscription node merge regression tests passed")
    }

    private static func node(_ name: String, outbound: String) -> ProxyNode {
        ProxyNode(name: name, protocol: .socks5, server: "example.com", port: 1080, singBoxOutboundJson: outbound)
    }
}
