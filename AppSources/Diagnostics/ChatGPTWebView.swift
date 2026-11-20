import SwiftUI
import UIKit
import WebKit

/// Isolated persistent website data store for the in-app ChatGPT page:
/// separate from Safari and any other WKWebView, but keeps the login across launches.
enum ChatGPTWebData {
    private static let storeId = UUID(uuidString: "6F1C2A4E-9B57-4C1D-8E3A-2D5B7F90A1C3")!

    @MainActor
    static var store: WKWebsiteDataStore { WKWebsiteDataStore(forIdentifier: storeId) }

    @MainActor
    static func clearAll() async {
        await store.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast)
    }
}

@MainActor
final class ChatGPTWebController: ObservableObject {
    weak var webView: WKWebView?

    func reload() { webView?.reload() }

    func goHome() {
        if let url = URL(string: "https://chatgpt.com/") { webView?.load(URLRequest(url: url)) }
    }
}

struct ChatGPTWebView: UIViewRepresentable {
    @ObservedObject var diagnostics: DiagnosticsStore
    let controller: ChatGPTWebController

    static let safariUserAgent =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"

    /// Wraps fetch / XHR at document start and reports `proofofwork.difficulty` from sentinel/chat-requirements responses.
    static let hookScript = #"""
    (function () {
      if (window.__gptguardHooked) { return; }
      window.__gptguardHooked = true;
      var RE = /sentinel\/chat-requirements/;
      function post(payload) {
        try { window.webkit.messageHandlers.gptguard.postMessage(payload); } catch (e) {}
      }
      function find(obj, depth) {
        if (!obj || typeof obj !== 'object' || depth > 6) { return null; }
        if (obj.proofofwork && typeof obj.proofofwork === 'object' && obj.proofofwork.difficulty != null) { return obj; }
        for (var k in obj) {
          if (Object.prototype.hasOwnProperty.call(obj, k)) {
            var r = find(obj[k], depth + 1);
            if (r) { return r; }
          }
        }
        return null;
      }
      function inspect(url, text) {
        try {
          var holder = find(JSON.parse(text), 0);
          if (!holder) { return; }
          post({
            difficulty: String(holder.proofofwork.difficulty),
            turnstile: !!(holder.turnstile && holder.turnstile.required),
            arkose: !!(holder.arkose && holder.arkose.required),
            persona: holder.persona ? String(holder.persona) : '',
            url: String(url).slice(0, 200)
          });
        } catch (e) {}
      }
      function urlOf(input) {
        try {
          if (typeof input === 'string') { return input; }
          if (input && typeof input === 'object' && 'url' in input) { return String(input.url); }
          return String(input);
        } catch (e) { return ''; }
      }
      var origFetch = window.fetch;
      if (typeof origFetch === 'function') {
        window.fetch = function (input, init) {
          var url = urlOf(input);
          var p = origFetch.apply(this, arguments);
          if (RE.test(url)) {
            p.then(function (resp) {
              try { resp.clone().text().then(function (t) { inspect(url, t); }, function () {}); } catch (e) {}
            }, function () {});
          }
          return p;
        };
      }
      var origOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url) {
        this.__gptguardUrl = urlOf(url);
        return origOpen.apply(this, arguments);
      };
      var origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        if (RE.test(xhr.__gptguardUrl || '')) {
          xhr.addEventListener('load', function () {
            try { inspect(xhr.__gptguardUrl, xhr.responseText); } catch (e) {}
          });
        }
        return origSend.apply(this, arguments);
      };
    })();
    """#

    func makeCoordinator() -> Coordinator { Coordinator(diagnostics: diagnostics) }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = ChatGPTWebData.store
        config.allowsInlineMediaPlayback = true
        let contentController = WKUserContentController()
        contentController.addUserScript(WKUserScript(source: Self.hookScript, injectionTime: .atDocumentStart, forMainFrameOnly: false))
        contentController.add(context.coordinator, name: "gptguard")
        config.userContentController = contentController

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.customUserAgent = Self.safariUserAgent
        webView.allowsBackForwardNavigationGestures = true
        webView.uiDelegate = context.coordinator
        webView.isOpaque = false
        webView.backgroundColor = UIColor(VpnTheme.bgDark)
        controller.webView = webView
        if let url = URL(string: "https://chatgpt.com/") {
            webView.load(URLRequest(url: url))
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    static func dismantleUIView(_ uiView: WKWebView, coordinator: Coordinator) {
        uiView.configuration.userContentController.removeScriptMessageHandler(forName: "gptguard")
    }

    @MainActor
    final class Coordinator: NSObject, WKScriptMessageHandler, WKUIDelegate {
        let diagnostics: DiagnosticsStore

        init(diagnostics: DiagnosticsStore) {
            self.diagnostics = diagnostics
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let body = message.body as? [String: Any],
                  let difficulty = body["difficulty"] as? String, !difficulty.isEmpty else { return }
            diagnostics.recordPow(
                difficulty: difficulty,
                turnstile: body["turnstile"] as? Bool ?? false,
                arkose: body["arkose"] as? Bool ?? false,
                persona: body["persona"] as? String ?? ""
            )
        }

        // Open target=_blank links in the same view instead of silently dropping them.
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if navigationAction.targetFrame == nil {
                webView.load(navigationAction.request)
            }
            return nil
        }
    }
}

/// Full-screen in-app ChatGPT with a live PoW indicator capsule.
struct ChatGPTWebScreen: View {
    @ObservedObject var diagnostics: DiagnosticsStore
    @StateObject private var controller = ChatGPTWebController()

    var body: some View {
        ChatGPTWebView(diagnostics: diagnostics, controller: controller)
            .ignoresSafeArea(edges: .bottom)
            .overlay(alignment: .topTrailing) { powCapsule.padding(10) }
            .navigationTitle("网页版 ChatGPT")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button { controller.goHome() } label: { Image(systemName: "house") }
                    Button { controller.reload() } label: { Image(systemName: "arrow.clockwise") }
                }
            }
    }

    private var powCapsule: some View {
        let pow = diagnostics.latestPow
        let color = pow?.risk.color ?? VpnTheme.textSecondary
        return HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(pow.map { "PoW \($0.risk.title) · \($0.difficulty)" } ?? "发一条消息以测 PoW")
                .font(.caption2.bold())
                .foregroundStyle(VpnTheme.textPrimary)
                .lineLimit(1)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(.ultraThinMaterial)
        .overlay(Capsule().stroke(color.opacity(0.7), lineWidth: 1))
        .clipShape(Capsule())
    }
}
