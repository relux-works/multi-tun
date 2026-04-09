import Foundation

// MARK: - AnyConnect SAML SSO v2 Protocol

struct SAMLFlowResult {
    let samlURL: String
    let opaqueXML: String
    let serverHost: String  // after redirects
}

/// Step 1: POST to ASA → get SAML login URL + opaque data.
func fetchSAMLConfig(server: String) -> SAMLFlowResult? {
    let initXML = """
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="init" aggregate-auth-version="2">\
    <version who="vpn">v9.12-unknown</version>\
    <device-id>mac-intel</device-id>\
    <capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>\
    <group-access>https://\(server)</group-access>\
    </config-auth>
    """

    // Step 1a: POST, don't follow redirects — just get Location header
    var targetURL = "https://\(server)"
    var finalHost = server

    let headProcess = Process()
    headProcess.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    headProcess.arguments = [
        "-s", "-D", "-",  // dump headers
        "-o", "/dev/null", // discard body
        "-X", "POST",
        "-H", "User-Agent: AnyConnect",
        "-H", "Content-Type: application/xml; charset=utf-8",
        "-H", "X-Aggregate-Auth: 1",
        "-d", initXML,
        targetURL
    ]

    let headPipe = Pipe()
    headProcess.standardOutput = headPipe
    headProcess.standardError = FileHandle.nullDevice

    do {
        try headProcess.run()
        headProcess.waitUntilExit()
    } catch {
        printError("curl redirect check failed: \(error)")
        return nil
    }

    let headData = headPipe.fileHandleForReading.readDataToEndOfFile()
    let headers = String(data: headData, encoding: .utf8) ?? ""

    for line in headers.components(separatedBy: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("location:") {
            let loc = trimmed.dropFirst("location:".count).trimmingCharacters(in: .whitespaces)
            targetURL = loc
            if let url = URL(string: loc), let host = url.host {
                let path = url.path.isEmpty ? "" : url.path
                finalHost = host + path
            }
            printInfo("ASA redirected to: \(finalHost)")
        }
    }

    // Step 1b: POST to the final URL (after redirect)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [
        "-s",
        "-X", "POST",
        "-H", "User-Agent: AnyConnect",
        "-H", "Content-Type: application/xml; charset=utf-8",
        "-H", "X-Aggregate-Auth: 1",
        "-H", "X-Transcend-Version: 1",
        "-d", initXML,
        targetURL
    ]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        printError("curl failed: \(error)")
        return nil
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let response = String(data: data, encoding: .utf8) ?? ""

    // Extract SAML URL from XML
    guard let samlURLMatch = response.range(of: "<sso-v2-login>", options: .literal),
          let samlURLEnd = response.range(of: "</sso-v2-login>", options: .literal) else {
        printError("no sso-v2-login found in ASA response")
        return nil
    }
    let samlURL = String(response[samlURLMatch.upperBound..<samlURLEnd.lowerBound])
        .replacingOccurrences(of: "&#x26;", with: "&")
        .replacingOccurrences(of: "&amp;", with: "&")

    // Extract opaque block
    guard let opaqueStart = response.range(of: "<opaque", options: .literal),
          let opaqueEnd = response.range(of: "</opaque>", options: .literal) else {
        printError("no opaque block found in ASA response")
        return nil
    }
    let opaqueXML = String(response[opaqueStart.lowerBound..<opaqueEnd.upperBound])

    // Extract host from final redirect or opaque
    if finalHost.contains("/") {
        // Already has path
    } else if let hostStart = response.range(of: "<host-name>"),
              let hostEnd = response.range(of: "</host-name>") {
        finalHost = String(response[hostStart.upperBound..<hostEnd.lowerBound])
    }

    printInfo("SAML URL: \(samlURL.prefix(80))...")
    printInfo("ASA host: \(finalHost)")

    return SAMLFlowResult(samlURL: samlURL, opaqueXML: opaqueXML, serverHost: finalHost)
}

/// Step 3: POST SAML token back to ASA → get session cookie.
func completeSAMLAuth(serverHost: String, opaqueXML: String, samlToken: String) -> (cookie: String, host: String)? {
    let replyXML = """
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">\
    <version who="vpn">v9.12-unknown</version>\
    <device-id>mac-intel</device-id>\
    <session-token/><session-id/>\
    \(opaqueXML)\
    <auth><sso-token>\(samlToken)</sso-token></auth>\
    </config-auth>
    """

    // POST to the ASA host (use the host from step 1 redirects)
    let baseHost = serverHost.components(separatedBy: "/").first ?? serverHost
    let path = serverHost.contains("/") ? "/" + serverHost.components(separatedBy: "/").dropFirst().joined(separator: "/") : ""

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [
        "-s",
        "-X", "POST",
        "-H", "User-Agent: AnyConnect",
        "-H", "Content-Type: application/xml; charset=utf-8",
        "-H", "X-Aggregate-Auth: 1",
        "-H", "X-Transcend-Version: 1",
        "-H", "Cookie: acSamlv2Token=\(samlToken)",
        "-d", replyXML,
        "https://\(baseHost)\(path)"
    ]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        printError("curl auth-reply failed: \(error)")
        return nil
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let response = String(data: data, encoding: .utf8) ?? ""

    // Extract session-token (this is the cookie for openconnect)
    if let tokenStart = response.range(of: "<session-token>"),
       let tokenEnd = response.range(of: "</session-token>") {
        let sessionToken = String(response[tokenStart.upperBound..<tokenEnd.lowerBound])
        if !sessionToken.isEmpty {
            printInfo("got session token from ASA")
            return (cookie: sessionToken, host: baseHost)
        }
    }

    // Maybe we got a webvpn cookie in the response
    if response.contains("webvpn") && response.contains("session-token") {
        printError("ASA response has session info but couldn't parse it")
    }

    printError("ASA auth-reply failed. Response:\n\(response.prefix(500))")
    return nil
}
