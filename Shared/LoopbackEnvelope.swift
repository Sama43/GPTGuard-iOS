import CryptoKit
import Foundation

/// Keep launch credentials private even if another process occupies the mirror's port.
struct LoopbackEnvelope {
    private let key: SymmetricKey
    let authorization: String

    init(token: String) {
        key = SymmetricKey(data: SHA256.hash(data: Data(("message:" + token).utf8)))
        authorization = Data(SHA256.hash(data: Data(("http:" + token).utf8))).base64EncodedString()
    }

    func seal(_ data: Data, for purpose: String) throws -> String {
        let box = try AES.GCM.seal(data, using: key, authenticating: Data(purpose.utf8))
        guard let combined = box.combined else { throw CocoaError(.coderInvalidValue) }
        return combined.base64EncodedString()
    }

    func open(_ base64: Data, for purpose: String) throws -> Data {
        guard let combined = Data(base64Encoded: base64) else { throw CocoaError(.coderReadCorrupt) }
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key, authenticating: Data(purpose.utf8))
    }
}
