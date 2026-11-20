import Foundation

/// Test-only stand-in so NodeUriParser compiles without the Yams package.
/// Clash YAML is never detected here, so these tests exercise only the URI / base64 / JSON paths.
enum ClashYamlParser {
    static func looksLikeClashYaml(_ text: String) -> Bool { false }
    static func parse(_ yamlText: String) -> ParseBatchResult { ParseBatchResult(nodes: [], errors: []) }
}
