import Foundation

enum SubscriptionNodeMerge {
    static func merge(_ incoming: [ProxyNode], with existing: [ProxyNode], subscriptionId: UUID) -> [ProxyNode] {
        var result = incoming.map { node in
            var tagged = node
            tagged.subscriptionId = subscriptionId
            return tagged
        }
        guard !existing.isEmpty else { return result }

        var oldByOutbound: [Data: [ProxyNode]] = [:]
        for node in existing {
            if let outbound = normalizedOutbound(node) {
                oldByOutbound[outbound, default: []].append(node)
            }
        }

        var newIndicesByOutbound: [Data: [Int]] = [:]
        for index in incoming.indices {
            if let outbound = normalizedOutbound(incoming[index]) {
                newIndicesByOutbound[outbound, default: []].append(index)
            }
        }

        for (outbound, indices) in newIndicesByOutbound {
            guard let candidates = oldByOutbound[outbound] else { continue }
            var candidatesByName = Dictionary(grouping: candidates.reversed(), by: \.name)
            var reusedIds = Set<UUID>()
            var unmatchedIndices: [Int] = []

            for index in indices {
                let name = result[index].name
                if let previous = candidatesByName[name]?.popLast() {
                    restoreMetadata(from: previous, to: &result[index])
                    reusedIds.insert(previous.id)
                } else {
                    unmatchedIndices.append(index)
                }
            }

            // A rename is safe to reconcile only when one old and one new entry remain for this outbound.
            if unmatchedIndices.count == 1,
               candidates.count - reusedIds.count == 1,
               let previous = candidates.first(where: { !reusedIds.contains($0.id) }) {
                restoreMetadata(from: previous, to: &result[unmatchedIndices[0]])
            }
        }
        return result
    }

    private static func normalizedOutbound(_ node: ProxyNode) -> Data? {
        let data = Data(node.singBoxOutboundJson.utf8)
        guard let outbound = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return nil
        }
        return try? JSONSerialization.data(withJSONObject: outbound, options: .sortedKeys)
    }

    private static func restoreMetadata(from previous: ProxyNode, to node: inout ProxyNode) {
        node.id = previous.id
        node.createdAt = previous.createdAt
        node.lastLatencyMs = previous.lastLatencyMs
        node.lastExitIp = previous.lastExitIp
        node.lastExitCountry = previous.lastExitCountry
        node.lastExitOrg = previous.lastExitOrg
    }
}
