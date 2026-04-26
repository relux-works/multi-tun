import AppKit
import WebKit
import Foundation

// MARK: - CLI argument parsing

struct CLIArgs {
    let url: String?
    let server: String?  // Full flow: --server vpn-gw1.corp.example/outside
    let timeout: TimeInterval
    let username: String?
    let password: String?
    let totpSecret: String?
    let manualOTPStdin: Bool

    var hasCredentials: Bool {
        username != nil && password != nil
    }

    var hasTOTP: Bool {
        totpSecret != nil
    }

    var isFullFlow: Bool {
        server != nil
    }

    static func parse() -> CLIArgs? {
        let args = CommandLine.arguments
        var url: String?
        var server: String?
        var timeout: TimeInterval = 300
        var username: String?
        var password: String?
        var totpSecret: String?
        var manualOTPStdin = false

        var i = 1
        while i < args.count {
            switch args[i] {
            case "--url":
                i += 1
                guard i < args.count else { printError("--url requires a value"); return nil }
                url = args[i]
            case "--server":
                i += 1
                guard i < args.count else { printError("--server requires a value"); return nil }
                server = args[i]
            case "--timeout":
                i += 1
                guard i < args.count, let t = TimeInterval(args[i]) else {
                    printError("--timeout requires a numeric value (seconds)"); return nil
                }
                timeout = t
            case "--username":
                i += 1
                guard i < args.count else { printError("--username requires a value"); return nil }
                username = args[i]
            case "--password":
                i += 1
                guard i < args.count else { printError("--password requires a value"); return nil }
                password = args[i]
            case "--totp-secret":
                i += 1
                guard i < args.count else { printError("--totp-secret requires a value"); return nil }
                totpSecret = args[i]
            case "--manual-otp-stdin":
                manualOTPStdin = true
            case "--help", "-h":
                printUsage(); exit(0)
            case "--version":
                print("vpn-auth 0.2.0"); exit(0)
            default:
                printError("unknown flag: \(args[i])"); return nil
            }
            i += 1
        }

        if url == nil && server == nil {
            printError("either --url or --server is required")
            return nil
        }
        return CLIArgs(url: url, server: server, timeout: timeout, username: username, password: password, totpSecret: totpSecret, manualOTPStdin: manualOTPStdin)
    }
}

func printUsage() {
    let usage = """
    vpn-auth — SAML VPN authentication via native WebView

    Usage:
      vpn-auth --server <host/path> [options]   Full flow (recommended)
      vpn-auth --url <auth-url> [options]        SAML URL only

    Options:
      --server       VPN server host/path (e.g. vpn-gw1.corp.example/outside)
      --url          Direct SAML authentication URL
      --username     Auto-fill username
      --password     Auto-fill password
      --totp-secret  Base32 TOTP secret (uses totp-cli instant)
      --manual-otp-stdin  Read SMS/manual OTP from stdin and submit it
      --timeout      Authentication timeout in seconds (default: 300)
      --version      Print version
      --help         Show this help

    Output:
      JSON to stdout: {"cookie":"...","host":"..."}
      With --server: outputs session cookie ready for openconnect
    """
    FileHandle.standardError.write(Data((usage + "\n").utf8))
}

func printError(_ message: String) {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
}

func printInfo(_ message: String) {
    FileHandle.standardError.write(Data("info: \(message)\n".utf8))
}

func outputJSON(_ dict: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: dict),
          let str = String(data: data, encoding: .utf8) else {
        printError("failed to serialize JSON output")
        exit(1)
    }
    print(str)
}

func outputError(_ message: String) -> Never {
    let dict: [String: Any] = ["error": message]
    if let data = try? JSONSerialization.data(withJSONObject: dict),
       let str = String(data: data, encoding: .utf8) {
        print(str)
    }
    exit(1)
}

func sanitizeLogURL(_ value: String) -> String {
    guard let url = URL(string: value) else {
        return String(value.prefix(240))
    }
    if url.scheme == "about" {
        return value
    }
    guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        return String(value.prefix(240))
    }
    components.user = nil
    components.password = nil
    components.query = nil
    components.fragment = nil
    return String((components.string ?? value).prefix(240))
}

func sanitizedWebViewURL(_ webView: WKWebView) -> String {
    guard let value = webView.url?.absoluteString else {
        return "(none)"
    }
    return sanitizeLogURL(value)
}

func navigationFailureSummary(_ error: Error) -> String {
    let nsError = error as NSError
    var parts = [
        "domain=\(nsError.domain)",
        "code=\(nsError.code)",
        "description=\(nsError.localizedDescription)"
    ]
    if let failingURL = nsError.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
        parts.append("failingURL=\(sanitizeLogURL(failingURL.absoluteString))")
    } else if let failingURL = nsError.userInfo[NSURLErrorFailingURLStringErrorKey] as? String {
        parts.append("failingURL=\(sanitizeLogURL(failingURL))")
    }
    return parts.joined(separator: " ")
}

struct PresetCookie: Decodable {
    let name: String
    let value: String
    let domain: String
    let path: String?
}

func loadPresetCookies(into store: WKHTTPCookieStore, completion: @escaping () -> Void) {
    guard let raw = ProcessInfo.processInfo.environment["VPN_AUTH_PRESET_COOKIES_JSON"],
          let data = raw.data(using: .utf8),
          let cookies = try? JSONDecoder().decode([PresetCookie].self, from: data),
          !cookies.isEmpty else {
        completion()
        return
    }

    printInfo("preloading cookies: \(cookies.map { $0.name }.joined(separator: ", "))")

    func install(_ index: Int) {
        if index >= cookies.count {
            completion()
            return
        }

        let cookie = cookies[index]
        let properties: [HTTPCookiePropertyKey: Any] = [
            .name: cookie.name,
            .value: cookie.value,
            .domain: cookie.domain,
            .path: cookie.path ?? "/",
            .secure: true,
        ]

        guard let httpCookie = HTTPCookie(properties: properties) else {
            install(index + 1)
            return
        }

        store.setCookie(httpCookie) {
            install(index + 1)
        }
    }

    install(0)
}

// MARK: - TOTP Generation (via totp-cli)

func generateTOTP(secret: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["totp-cli", "instant"]
    process.environment = ProcessInfo.processInfo.environment.merging(
        ["TOTP_TOKEN": secret], uniquingKeysWith: { _, new in new }
    )

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        printError("failed to run totp-cli: \(error)")
        return nil
    }

    guard process.terminationStatus == 0 else {
        printError("totp-cli exited with status \(process.terminationStatus)")
        return nil
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let code = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    return code
}

// MARK: - JS Injection Scripts

/// Keycloak login form: fill username when visible, always fill password, submit.
func loginFormScript(username: String, password: String) -> String {
    // Some Keycloak SSO pages use Vue.js custom input components.
    // We need to set the underlying <input> values and dispatch events for Vue reactivity.
    return """
    (function() {
        function fillAndSubmit() {
            var userInput = document.querySelector('#username')
                         || document.querySelector('input[name="username"]')
                         || document.querySelector('input[type="email"]')
                         || document.querySelector('input[autocomplete="username"]');
            var passInput = document.querySelector('#password')
                         || document.querySelector('input[name="password"]')
                         || document.querySelector('input[type="password"]')
                         || document.querySelector('input[autocomplete="current-password"]');
            if (!passInput) return false;

            function setNativeValue(el, value) {
                var proto = Object.getPrototypeOf(el);
                var setter = Object.getOwnPropertyDescriptor(proto, 'value') ||
                             Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                if (setter && setter.set) {
                    setter.set.call(el, value);
                } else {
                    el.value = value;
                }
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }

            if (userInput) {
                setNativeValue(userInput, '\(username.replacingOccurrences(of: "'", with: "\\'"))');
            }
            setNativeValue(passInput, '\(password.replacingOccurrences(of: "'", with: "\\'"))');

            // Small delay for Vue reactivity to process
            setTimeout(function() {
                var form = document.querySelector('form');
                if (form) {
                    var submitBtn = form.querySelector('button[type="submit"], input[type="submit"], .button');
                    if (submitBtn) {
                        submitBtn.click();
                    } else {
                        form.submit();
                    }
                }
            }, 300);
            return true;
        }

        // Try immediately, then poll (page may still be loading Vue)
        if (!fillAndSubmit()) {
            var attempts = 0;
            var interval = setInterval(function() {
                attempts++;
                if (fillAndSubmit() || attempts > 20) {
                    clearInterval(interval);
                }
            }, 500);
        }
    })();
    """
}

/// Username-only form: fill username/email, submit, then wait for the password page.
func usernameOnlyFormScript(username: String) -> String {
    return """
    (function() {
        function fillAndSubmit() {
            var userInput = document.querySelector('#username')
                         || document.querySelector('input[name="username"]')
                         || document.querySelector('input[type="email"]')
                         || document.querySelector('input[autocomplete="username"]');
            if (!userInput) return false;

            function setNativeValue(el, value) {
                var proto = Object.getPrototypeOf(el);
                var setter = Object.getOwnPropertyDescriptor(proto, 'value') ||
                             Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                if (setter && setter.set) {
                    setter.set.call(el, value);
                } else {
                    el.value = value;
                }
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }

            setNativeValue(userInput, '\(username.replacingOccurrences(of: "'", with: "\\'"))');

            setTimeout(function() {
                var form = userInput.closest('form') || document.querySelector('form');
                if (form) {
                    var submitBtn = form.querySelector('button[type="submit"], input[type="submit"], .button');
                    if (submitBtn) {
                        submitBtn.click();
                    } else {
                        form.submit();
                    }
                }
            }, 300);
            return true;
        }

        if (!fillAndSubmit()) {
            var attempts = 0;
            var interval = setInterval(function() {
                attempts++;
                if (fillAndSubmit() || attempts > 20) {
                    clearInterval(interval);
                }
            }, 500);
        }
    })();
    """
}

/// OTP form: fill TOTP code, submit.
func otpFormScript(code: String) -> String {
    return """
    (function() {
        function fillAndSubmit() {
            // Keycloak OTP field: input named 'otp' or 'totp' or type='tel' for code
            var otpInput = document.querySelector('input[name="otp"]')
                        || document.querySelector('input[name="totp"]')
                        || document.querySelector('input[id="otp"]')
                        || document.querySelector('input[autocomplete="one-time-code"]')
                        || document.querySelector('input[type="tel"]')
                        || document.querySelector('input[type="number"]');
            if (!otpInput) return false;

            var proto = Object.getPrototypeOf(otpInput);
            var setter = Object.getOwnPropertyDescriptor(proto, 'value') ||
                         Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
            if (setter && setter.set) {
                setter.set.call(otpInput, '\(code)');
            } else {
                otpInput.value = '\(code)';
            }
            otpInput.dispatchEvent(new Event('input', { bubbles: true }));
            otpInput.dispatchEvent(new Event('change', { bubbles: true }));

            setTimeout(function() {
                var form = otpInput.closest('form');
                if (form) {
                    var submitBtn = form.querySelector('button[type="submit"], input[type="submit"], .button');
                    if (submitBtn) {
                        submitBtn.click();
                    } else {
                        form.submit();
                    }
                }
            }, 300);
            return true;
        }

        if (!fillAndSubmit()) {
            var attempts = 0;
            var interval = setInterval(function() {
                attempts++;
                if (fillAndSubmit() || attempts > 20) {
                    clearInterval(interval);
                }
            }, 500);
        }
    })();
    """
}

/// Detect what page we're on: 'login', 'username_only', 'otp', or 'unknown'.
func pageDetectionScript() -> String {
    return """
    (function() {
        var userInput = document.querySelector('#username')
            || document.querySelector('input[name="username"]')
            || document.querySelector('input[type="email"]')
            || document.querySelector('input[autocomplete="username"]');
        var hasSubmit = !!(document.querySelector('form')
            || document.querySelector('button[type="submit"]')
            || document.querySelector('input[type="submit"]')
            || document.querySelector('button[name="login"]'));
        if (document.querySelector('#password')
            || document.querySelector('input[name="password"]')
            || document.querySelector('input[type="password"]')
            || document.querySelector('input[autocomplete="current-password"]')) return 'login';
        if (document.querySelector('input[name="otp"]')
            || document.querySelector('input[name="totp"]')
            || document.querySelector('input[id="otp"]')
            || document.querySelector('input[autocomplete="one-time-code"]')) return 'otp';
        if (userInput && hasSubmit) return 'username_only';
        return 'unknown';
    })();
    """
}

/// Emit a safe snapshot for pages we do not recognize yet.
func unknownPageSnapshotScript() -> String {
    return """
    (function() {
        function sanitizeURL(value) {
            try {
                var url = new URL(value, window.location.href);
                if (url.protocol === 'about:' || url.origin === 'null') {
                    return url.href;
                }
                return url.origin + url.pathname;
            } catch (_) {
                return value || '';
            }
        }

        function truncate(value, limit) {
            value = value || '';
            return value.length > limit ? value.slice(0, limit) : value;
        }

        function summarizeInput(el) {
            return {
                type: el.type || '',
                name: el.name || '',
                id: el.id || '',
                autocomplete: el.autocomplete || ''
            };
        }

        function summarizeForm(el) {
            return {
                action: sanitizeURL(el.action || ''),
                method: (el.method || '').toLowerCase()
            };
        }

        function summarizeFrame(el) {
            return truncate(sanitizeURL(el.src || ''), 160);
        }

        var payload = {
            title: truncate(document.title || '', 160),
            readyState: document.readyState || '',
            url: sanitizeURL(window.location.href),
            online: navigator.onLine,
            bodyTextLength: (document.body && document.body.innerText ? document.body.innerText.length : 0),
            htmlLength: (document.documentElement && document.documentElement.outerHTML ? document.documentElement.outerHTML.length : 0),
            forms: Array.from(document.forms || []).slice(0, 6).map(summarizeForm),
            inputs: Array.from(document.querySelectorAll('input')).slice(0, 12).map(summarizeInput),
            iframes: Array.from(document.querySelectorAll('iframe')).slice(0, 6).map(summarizeFrame)
        };

        return JSON.stringify(payload);
    })();
    """
}

// MARK: - App Delegate

class AuthAppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var navigationHandler: AuthNavigationDelegate!
    var timeoutTimer: Timer?
    let args: CLIArgs
    let effectiveURL: String
    let samlFlow: SAMLFlowResult?
    private var loginAttempted = false
    private var usernameOnlyAttempted = false
    private var lastSubmittedOTPCode = ""
    private var lastUnknownSnapshot = ""
    private var repeatedUnknownSnapshotCount = 0
    private var manualOTPReadInProgress = false

    init(args: CLIArgs, url: String, samlFlow: SAMLFlowResult?) {
        self.args = args
        self.effectiveURL = url
        self.samlFlow = samlFlow
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()

        // Clear old cookies/cache to avoid stale SSO sessions
        let dataStore = config.websiteDataStore
        dataStore.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                            modifiedSince: Date.distantPast) {
            printInfo("cleared WebView data store")
        }

        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 480, height: 640), configuration: config)
        navigationHandler = AuthNavigationDelegate(samlFlow: samlFlow)
        webView.navigationDelegate = navigationHandler

        config.websiteDataStore.httpCookieStore.add(navigationHandler)

        // Window — show if manual mode, minimize if auto mode
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 640),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "VPN Authentication"
        window.contentView = webView
        window.center()

        if args.hasCredentials {
            printInfo("auto-login mode (credentials provided)")
            // Still show window — useful for debugging, can hide later
        } else {
            printInfo("manual mode — please log in via the window")
        }
        window.makeKeyAndOrderFront(nil)

        guard let url = URL(string: effectiveURL) else {
            outputError("invalid URL: \(effectiveURL)")
        }
        loadPresetCookies(into: config.websiteDataStore.httpCookieStore) {
            self.webView.load(URLRequest(url: url))
        }

        // Poll for page changes to inject credentials
        if args.hasCredentials || args.manualOTPStdin {
            Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] timer in
                self?.checkPageAndAutoFill(timer: timer)
            }
        }

        timeoutTimer = Timer.scheduledTimer(withTimeInterval: args.timeout, repeats: false) { _ in
            outputError("authentication timed out after \(Int(self.args.timeout))s")
        }
    }

    private func checkPageAndAutoFill(timer: Timer) {
        webView.evaluateJavaScript(pageDetectionScript()) { [weak self] result, error in
            guard let self = self, let pageType = result as? String else {
                if let error = error { printError("page detect error: \(error)") }
                return
            }
            printInfo("page type: \(pageType)")

            switch pageType {
            case "login":
                self.lastUnknownSnapshot = ""
                self.repeatedUnknownSnapshotCount = 0
                if !self.loginAttempted, let username = self.args.username, let password = self.args.password {
                    self.loginAttempted = true
                    printInfo("detected login page — auto-filling credentials")
                    let script = loginFormScript(username: username, password: password)
                    self.webView.evaluateJavaScript(script) { _, err in
                        if let err = err { printError("login injection error: \(err)") }
                    }
                }

            case "username_only":
                self.lastUnknownSnapshot = ""
                self.repeatedUnknownSnapshotCount = 0
                if !self.usernameOnlyAttempted, let username = self.args.username {
                    self.usernameOnlyAttempted = true
                    printInfo("detected username-only page — auto-filling username")
                    let script = usernameOnlyFormScript(username: username)
                    self.webView.evaluateJavaScript(script) { _, err in
                        if let err = err { printError("username-only injection error: \(err)") }
                    }
                }

            case "otp":
                self.lastUnknownSnapshot = ""
                self.repeatedUnknownSnapshotCount = 0
                if let secret = self.args.totpSecret {
                    printInfo("detected OTP page — generating TOTP code")
                    guard let code = generateTOTP(secret: secret) else {
                        printError("TOTP generation failed — falling back to manual entry")
                        return
                    }
                    if code == self.lastSubmittedOTPCode {
                        return
                    }
                    self.lastSubmittedOTPCode = code
                    printInfo("generated TOTP code")
                    let script = otpFormScript(code: code)
                    self.webView.evaluateJavaScript(script) { _, err in
                        if let err = err { printError("OTP injection error: \(err)") }
                    }
                } else if self.args.manualOTPStdin {
                    self.requestManualOTPFromStdin()
                }

            default:
                self.webView.evaluateJavaScript(unknownPageSnapshotScript()) { result, err in
                    if let err = err {
                        printError("unknown page snapshot error: \(err)")
                        return
                    }
                    guard let snapshot = result as? String else {
                        return
                    }
                    if snapshot != self.lastUnknownSnapshot {
                        self.lastUnknownSnapshot = snapshot
                        self.repeatedUnknownSnapshotCount = 1
                        printInfo("unknown page snapshot: \(snapshot)")
                    } else {
                        self.repeatedUnknownSnapshotCount += 1
                    }
                    if self.isBlankUnknownSnapshot(snapshot) {
                        if self.repeatedUnknownSnapshotCount == 10 {
                            printError("blank WebView page still present after \(self.repeatedUnknownSnapshotCount)s; check DNS/routing for the SAML IdP")
                        }
                        if self.repeatedUnknownSnapshotCount >= 30 {
                            outputError("blank WebView page persisted for \(self.repeatedUnknownSnapshotCount)s; check DNS/routing for the SAML IdP")
                        }
                    }
                }
                break
            }
        }
    }

    private func requestManualOTPFromStdin() {
        if manualOTPReadInProgress {
            return
        }
        manualOTPReadInProgress = true
        printInfo("detected OTP page — waiting for manual code on stdin")
        printInfo("manual OTP required — enter code in terminal and press Return")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let rawCode = readLine()
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.manualOTPReadInProgress = false
                guard let code = rawCode?.trimmingCharacters(in: .whitespacesAndNewlines), !code.isEmpty else {
                    printError("manual OTP stdin was empty")
                    return
                }
                self.lastSubmittedOTPCode = code
                printInfo("received manual OTP code")
                let script = otpFormScript(code: code)
                self.webView.evaluateJavaScript(script) { _, err in
                    if let err = err { printError("manual OTP injection error: \(err)") }
                }
            }
        }
    }

    private func isBlankUnknownSnapshot(_ snapshot: String) -> Bool {
        guard let data = snapshot.data(using: .utf8),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        let url = payload["url"] as? String ?? ""
        let bodyTextLength = payload["bodyTextLength"] as? Int ?? 0
        let htmlLength = payload["htmlLength"] as? Int ?? 0
        let forms = payload["forms"] as? [Any] ?? []
        let inputs = payload["inputs"] as? [Any] ?? []
        let iframes = payload["iframes"] as? [Any] ?? []
        return (url == "about:blank" || url == "nullblank") &&
            bodyTextLength == 0 &&
            htmlLength <= 80 &&
            forms.isEmpty &&
            inputs.isEmpty &&
            iframes.isEmpty
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

// MARK: - Navigation Delegate (auth completion detection)

class AuthNavigationDelegate: NSObject, WKNavigationDelegate, WKHTTPCookieStoreObserver {
    private var completed = false
    let samlFlow: SAMLFlowResult?

    init(samlFlow: SAMLFlowResult?) {
        self.samlFlow = samlFlow
        super.init()
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {

        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

        let urlString = url.absoluteString
        printInfo("navigation: \(sanitizeLogURL(urlString))")

        // AnyConnect SSO-v2 localhost callback
        if urlString.hasPrefix("http://localhost:29786/") {
            let pathComponents = url.pathComponents
            if let token = pathComponents.last, token != "/" {
                completeAuth(cookie: token, cookieName: "localhost-callback", host: url.host ?? "", url: urlString)
                decisionHandler(.cancel)
                return
            }
        }

        // Detect the sso-v2-login-final page (Cisco SAML completion page)
        if urlString.contains("saml_ac_login.html") || urlString.contains("+CSCOE+/saml") {
            // Check cookies after a short delay (cookie may be set on this redirect)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                    for cookie in cookies {
                        if cookie.name == "acSamlv2Token" {
                            self.completeAuth(cookie: cookie.value, cookieName: cookie.name, host: cookie.domain, url: urlString, cookies: cookies)
                            return
                        }
                    }
                }
            }
        }

        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        printInfo("navigation commit: \(sanitizedWebViewURL(webView))")
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let title = String((webView.title ?? "").prefix(160))
        printInfo("navigation finish: url=\(sanitizedWebViewURL(webView)) title=\(title)")
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        printError("navigation failed: url=\(sanitizedWebViewURL(webView)) \(navigationFailureSummary(error))")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        printError("navigation provisional failed: url=\(sanitizedWebViewURL(webView)) \(navigationFailureSummary(error))")
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        printError("web content process terminated: url=\(sanitizedWebViewURL(webView))")
    }

    func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        guard !completed else { return }
        cookieStore.getAllCookies { cookies in
            for cookie in cookies {
                if cookie.name == "acSamlv2Token" || cookie.name == "webvpn" {
                    self.completeAuth(cookie: cookie.value, cookieName: cookie.name, host: cookie.domain, url: "", cookies: cookies)
                    return
                }
            }
        }
    }

    private func completeAuth(cookie: String, cookieName: String, host: String, url: String, cookies: [HTTPCookie] = []) {
        guard !completed else { return }
        completed = true
        let cookieSummary = cookies.map { "\($0.name) domain=\($0.domain) path=\($0.path)" }.joined(separator: " | ")
        if !cookieSummary.isEmpty {
            printInfo("cookie inventory: \(cookieSummary)")
        }
        printInfo("trigger cookie: \(cookieName)")

        // If full flow — complete SAML handshake with ASA to get session cookie
        if let flow = samlFlow {
            printInfo("got SAML token — completing ASA handshake...")
            if let session = completeSAMLAuth(
                serverHost: flow.serverHost,
                opaqueXML: flow.opaqueXML,
                samlToken: cookie
            ) {
                printInfo("got VPN session cookie!")
                let result: [String: Any] = [
                    "cookie": session.cookie,
                    "host": session.host,
                    "timestamp": ISO8601DateFormatter().string(from: Date()),
                ]
                outputJSON(result)
            } else {
                // Fallback: output the SAML token directly
                printError("ASA handshake failed — outputting raw SAML token")
                let result: [String: Any] = [
                    "cookie": cookie,
                    "host": host,
                    "saml_token": true,
                    "timestamp": ISO8601DateFormatter().string(from: Date()),
                ]
                outputJSON(result)
            }
        } else {
            printInfo("auth complete! Got token cookie.")
            let result: [String: Any] = [
                "cookie": cookie,
                "cookie_name": cookieName,
                "cookies": cookies.map { [
                    "name": $0.name,
                    "value": $0.value,
                    "domain": $0.domain,
                    "path": $0.path,
                ] },
                "host": host,
                "url": url,
                "timestamp": ISO8601DateFormatter().string(from: Date()),
            ]
            outputJSON(result)
        }

        DispatchQueue.main.async {
            NSApplication.shared.terminate(nil)
        }
    }
}

// MARK: - Entry point

guard let args = CLIArgs.parse() else {
    exit(1)
}

// Verify totp-cli is available if TOTP secret provided
if args.hasTOTP {
    let check = Process()
    check.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    check.arguments = ["which", "totp-cli"]
    check.standardOutput = FileHandle.nullDevice
    check.standardError = FileHandle.nullDevice
    try? check.run()
    check.waitUntilExit()
    if check.terminationStatus != 0 {
        printError("totp-cli not found — install with: brew install totp-cli")
        exit(1)
    }
}

// Full flow: --server → fetch SAML config from ASA first
var samlFlow: SAMLFlowResult?
var effectiveURL: String

if let server = args.server {
    printInfo("full flow: fetching SAML config from \(server)...")
    guard let flow = fetchSAMLConfig(server: server) else {
        outputError("failed to get SAML config from ASA")
    }
    samlFlow = flow
    effectiveURL = flow.samlURL
} else {
    effectiveURL = args.url!
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)

let delegate = AuthAppDelegate(args: args, url: effectiveURL, samlFlow: samlFlow)
app.delegate = delegate
app.run()
