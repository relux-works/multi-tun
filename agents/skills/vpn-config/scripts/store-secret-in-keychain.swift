#!/usr/bin/env swift
import Foundation
import Security

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(2)
}

guard CommandLine.arguments.count == 3 else {
    fail("usage: store-secret-in-keychain.swift ACCOUNT SERVICE")
}

let account = CommandLine.arguments[1]
let service = CommandLine.arguments[2]
guard !account.isEmpty, !service.isEmpty else {
    fail("account and service must not be empty")
}

let raw = FileHandle.standardInput.readDataToEndOfFile()
guard var secret = String(data: raw, encoding: .utf8) else {
    fail("secret must be UTF-8")
}
secret = secret.trimmingCharacters(in: .whitespacesAndNewlines)
guard !secret.isEmpty,
      secret.range(of: "^[A-Z2-7]+$", options: .regularExpression) != nil else {
    fail("secret must be unpadded uppercase base32")
}

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: account,
    kSecAttrService as String: service,
]
let value = Data(secret.utf8)
let updateStatus = SecItemUpdate(
    query as CFDictionary,
    [kSecValueData as String: value] as CFDictionary
)

if updateStatus == errSecItemNotFound {
    var add = query
    add[kSecValueData as String] = value
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
    let addStatus = SecItemAdd(add as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
        fail("Keychain insert failed with status \(addStatus)")
    }
} else if updateStatus != errSecSuccess {
    fail("Keychain update failed with status \(updateStatus)")
}

print("Stored TOTP secret in Keychain account '\(account)' for service '\(service)'.")
