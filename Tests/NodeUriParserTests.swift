import Foundation

@main
struct NodeUriParserTests {
    static func main() throws {
        let uri = "anytls://p%40ss@example.com:8443/?sni=cdn.example.com&insecure=1&fp=chrome&alpn=h2,http/1.1#%E7%BE%8E%E5%9B%BD-AnyTLS"
        let node = try NodeUriParser.parseSingleUri(uri)
        precondition(node.protocol == .anytls && node.name == "美国-AnyTLS")
        precondition(node.server == "example.com" && node.port == 8443)
        let outbound = try JSONSerialization.jsonObject(with: Data(node.singBoxOutboundJson.utf8)) as! [String: Any]
        precondition(outbound["type"] as? String == "anytls")
        precondition(outbound["password"] as? String == "p@ss")
        precondition(outbound["server_port"] as? Int == 8443)
        let tls = outbound["tls"] as! [String: Any]
        precondition(tls["enabled"] as? Bool == true && tls["server_name"] as? String == "cdn.example.com")
        precondition(tls["insecure"] as? Bool == true && tls["alpn"] as? [String] == ["h2", "http/1.1"])
        precondition((tls["utls"] as? [String: Any])?["fingerprint"] as? String == "chrome")

        // Defaults: port 443, SNI falls back to the server, generated name.
        let bare = try NodeUriParser.parseSingleUri("anytls://secret@1.2.3.4")
        precondition(bare.port == 443 && bare.name == "AnyTLS-1.2.3.4:443")
        let bareTls = (try JSONSerialization.jsonObject(with: Data(bare.singBoxOutboundJson.utf8)) as! [String: Any])["tls"] as! [String: Any]
        precondition(bareTls["server_name"] as? String == "1.2.3.4" && bareTls["insecure"] == nil)

        // Mixed base64 subscription keeps AnyTLS alongside other protocols.
        let body = Data("anytls://a@h1.example:443#A\nvless://00000000-0000-0000-0000-000000000000@h2.example:443#B".utf8).base64EncodedString()
        let batch = NodeUriParser.parseInput(body)
        precondition(batch.errors.isEmpty && batch.nodes.map { $0.protocol } == [.anytls, .vless])

        // Raw sing-box JSON is labeled AnyTLS.
        let raw = NodeUriParser.parseInput(#"{"type":"anytls","tag":"X","server":"h","server_port":443,"password":"p","tls":{"enabled":true}}"#)
        precondition(raw.nodes.first?.protocol == .anytls)

        // Missing password is rejected.
        precondition((try? NodeUriParser.parseSingleUri("anytls://@example.com:443")) == nil)
        print("NodeUriParserTests passed")
    }
}
