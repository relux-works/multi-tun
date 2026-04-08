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
        return CLIArgs(url: url, server: server, timeout: timeout, username: username, password: password, totpSecret: totpSecret)
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

/// Detect what page we're on: 'login', 'otp', or 'unknown'.
func pageDetectionScript() -> String {
    return """
    (function() {
        if (document.querySelector('#password')
            || document.querySelector('input[name="password"]')
            || document.querySelector('input[type="password"]')
            || document.querySelector('input[autocomplete="current-password"]')) return 'login';
        if (document.querySelector('input[name="otp"]')
            || document.querySelector('input[name="totp"]')
            || document.querySelector('input[id="otp"]')
            || document.querySelector('input[autocomplete="one-time-code"]')) return 'otp';
        return 'unknown';
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
    private var lastSubmittedOTPCode = ""

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
        if args.hasCredentials {
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
                if !self.loginAttempted, let username = self.args.username, let password = self.args.password {
                    self.loginAttempted = true
                    printInfo("detected login page — auto-filling credentials")
                    let script = loginFormScript(username: username, password: password)
                    self.webView.evaluateJavaScript(script) { _, err in
                        if let err = err { printError("login injection error: \(err)") }
                    }
                }

            case "otp":
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
                    printInfo("generated TOTP: \(code)")
                    let script = otpFormScript(code: code)
                    self.webView.evaluateJavaScript(script) { _, err in
                        if let err = err { printError("OTP injection error: \(err)") }
                    }
                }

            default:
                break
            }
        }
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
        printInfo("navigation: \(urlString.prefix(120))")

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
        let cookieSummary = cookies.map { "\($0.name)=\($0.value) domain=\($0.domain) path=\($0.path)" }.joined(separator: " | ")
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
