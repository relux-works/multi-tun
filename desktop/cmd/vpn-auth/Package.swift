// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "vpn-auth",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "vpn-auth",
            path: "Sources/vpn-auth"
        ),
    ]
)
