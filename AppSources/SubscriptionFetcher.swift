import Foundation

struct SubscriptionFetchMeta {
    let suggestedName: String?
    let uploadBytes: Int64?
    let downloadBytes: Int64?
    let totalBytes: Int64?
    let expireTimestampSec: Int64?
    let fetchedViaProxy: Bool
}

/// Streams chunked HTTP response bodies with strict HTTPS-only redirects and a hard byte cap,
/// avoiding byte-by-byte AsyncBytes overhead on multi-megabyte Clash YAML subscriptions.
private final class BoundedHTTPSFetchDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let maximumBytes: Int
    private let lock = NSLock()
    private var buffer = Data()
    private var response: HTTPURLResponse?
    private var overflowed = false
    private var continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>?

    init(maximumBytes: Int) {
        self.maximumBytes = maximumBytes
    }

    func fetch(request: URLRequest, configuration: URLSessionConfiguration) async throws -> (Data, HTTPURLResponse) {
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                lock.lock()
                continuation = cont
                lock.unlock()
                task.resume()
            }
        } onCancel: {
            task.cancel()
            session.invalidateAndCancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme?.lowercased() == "https" ? request : nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > Int64(maximumBytes) {
            lock.lock()
            overflowed = true
            lock.unlock()
            completionHandler(.cancel)
            return
        }
        lock.lock()
        self.response = http
        if response.expectedContentLength > 0 {
            buffer.reserveCapacity(min(Int(response.expectedContentLength), maximumBytes))
        }
        lock.unlock()
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        if buffer.count + data.count > maximumBytes {
            overflowed = true
            lock.unlock()
            dataTask.cancel()
            return
        }
        buffer.append(data)
        lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { session.finishTasksAndInvalidate() }
        lock.lock()
        let cont = continuation
        continuation = nil
        let didOverflow = overflowed
        let resp = response
        let data = buffer
        lock.unlock()

        guard let cont else { return }
        if didOverflow {
            cont.resume(throwing: URLError(.dataLengthExceedsMaximum))
            return
        }
        if let error {
            cont.resume(throwing: error)
            return
        }
        guard let resp else {
            cont.resume(throwing: URLError(.badServerResponse))
            return
        }
        cont.resume(returning: (data, resp))
    }
}

enum SubscriptionFetcher {
    private static let maximumBytes = 8 * 1024 * 1024

    private static let userAgents = ["clash-verge/v2.0.0", "v2rayNG/1.9.25"]

    static func fetchAndParse(
        urlString: String,
        activeCorePort: Int?,
        allowDirectBootstrap: Bool
    ) async throws -> (SubscriptionFetchMeta, ParseBatchResult) {
        guard let url = URL(string: urlString),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else {
            throw NSError(domain: "SubFetcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "请输入有效的 HTTPS 订阅链接"])
        }

        let useProxy = (activeCorePort ?? 0) > 0
        if !useProxy && !allowDirectBootstrap {
            throw NSError(domain: "SubFetcher", code: 2, userInfo: [NSLocalizedDescriptionKey: "当前未连代理且未开启直连拉取订阅开关"])
        }

        let cfg: URLSessionConfiguration
        if useProxy, let port = activeCorePort {
            cfg = ExitIpVerifier.makeStrictlyProxiedConfiguration(corePort: port, timeoutSec: 18)
        } else {
            let ephemeral = URLSessionConfiguration.ephemeral
            ephemeral.timeoutIntervalForRequest = 18
            ephemeral.timeoutIntervalForResource = 25
            ephemeral.requestCachePolicy = .reloadIgnoringLocalCacheData
            cfg = ephemeral
        }

        var lastError = "未知错误"
        for ua in userAgents {
            try Task.checkCancellation()
            do {
                var req = URLRequest(url: url)
                req.setValue(ua, forHTTPHeaderField: "User-Agent")
                req.setValue("*/*", forHTTPHeaderField: "Accept")

                let fetcher = BoundedHTTPSFetchDelegate(maximumBytes: maximumBytes)
                let (data, http) = try await fetcher.fetch(request: req, configuration: cfg)
                try Task.checkCancellation()
                guard (200...299).contains(http.statusCode) else {
                    throw NSError(domain: "SubFetcher", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "HTTP \(http.statusCode)"])
                }
                guard let body = String(data: data, encoding: .utf8), !body.isEmpty else {
                    throw NSError(domain: "SubFetcher", code: 3, userInfo: [NSLocalizedDescriptionKey: "订阅返回空内容"])
                }

                let parsed = NodeUriParser.parseInput(body)
                if !parsed.nodes.isEmpty {
                    let userInfo = parseUserInfo(http.value(forHTTPHeaderField: "subscription-userinfo"))
                    let suggested = parseDispositionName(http.value(forHTTPHeaderField: "content-disposition"))
                    let meta = SubscriptionFetchMeta(
                        suggestedName: suggested,
                        uploadBytes: userInfo["upload"],
                        downloadBytes: userInfo["download"],
                        totalBytes: userInfo["total"],
                        expireTimestampSec: userInfo["expire"],
                        fetchedViaProxy: useProxy
                    )
                    return (meta, parsed)
                }
                lastError = parsed.errors.first ?? "未解析到有效节点"
            } catch let error as URLError where error.code == .dataLengthExceedsMaximum {
                throw NSError(domain: "SubFetcher", code: 5, userInfo: [NSLocalizedDescriptionKey: "订阅超过 8 MiB 上限"])
            } catch {
                try Task.checkCancellation()
                lastError = error.localizedDescription
            }
        }

        throw NSError(domain: "SubFetcher", code: 4, userInfo: [NSLocalizedDescriptionKey: "拉取机场订阅失败: \(lastError)"])
    }

    private static func parseUserInfo(_ header: String?) -> [String: Int64] {
        guard let header = header, !header.isEmpty else { return [:] }
        var out: [String: Int64] = [:]
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1)
            if kv.count == 2,
               let v = Int64(kv[1].trimmingCharacters(in: .whitespaces)), v >= 0 {
                out[kv[0].trimmingCharacters(in: .whitespaces).lowercased()] = v
            }
        }
        return out
    }

    private static func parseDispositionName(_ header: String?) -> String? {
        guard let header = header else { return nil }
        if let range = header.range(of: "filename*=UTF-8''", options: .caseInsensitive) {
            let tail = String(header[range.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
            return tail.removingPercentEncoding?
                .replacingOccurrences(of: ".yaml", with: "")
                .replacingOccurrences(of: ".yml", with: "")
        }
        if let range = header.range(of: "filename=", options: .caseInsensitive) {
            let tail = String(header[range.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
            return tail.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
                .replacingOccurrences(of: ".yaml", with: "")
                .replacingOccurrences(of: ".yml", with: "")
        }
        return nil
    }
}
