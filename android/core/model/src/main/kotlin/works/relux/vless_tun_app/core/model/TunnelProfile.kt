package works.relux.vless_tun_app.core.model

import java.net.URI

enum class TunnelSourceMode(
    val title: String,
    val subtitle: String,
) {
    ProxyResolver(
        title = "Proxy Resolver",
        subtitle = "Resolve through the app-managed source URL before bootstrapping VLESS.",
    ),
    DirectVless(
        title = "Direct VLESS",
        subtitle = "Use the explicit VLESS endpoint directly with no resolver hop.",
    ),
}

data class TunnelProfile(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val transport: String,
    val sourceMode: TunnelSourceMode,
    val sourceUrl: String,
    val serverName: String,
    val uuid: String,
    val security: String = "",
    val serviceName: String = "",
    val fingerprint: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val flow: String = "",
)

fun TunnelProfile.endpoint(): String = if (host.isBlank()) {
    "Source-managed endpoint"
} else {
    "$host:$port"
}

fun TunnelProfile.sourceSummary(): String = when (sourceMode) {
    TunnelSourceMode.ProxyResolver -> sourceUrl.toResolverSummary()
    TunnelSourceMode.DirectVless -> sourceUrl.toDirectSummary(serverName)
}

private fun String.toResolverSummary(): String {
    val trimmed = trim()
    if (trimmed.isBlank()) {
        return "Resolver: Source URL not configured"
    }
    val scheme = runCatching { URI(trimmed).scheme?.lowercase() }.getOrNull()
    return when (scheme) {
        "http", "https" -> "Resolver: Source URL configured"
        "vless" -> "Resolver: Inline VLESS source"
        else -> "Resolver: Source configured"
    }
}

private fun String.toDirectSummary(serverName: String): String {
    val trimmed = trim()
    if (trimmed.startsWith("vless://", ignoreCase = true)) {
        return "Direct: Inline VLESS source"
    }
    if (serverName.isNotBlank()) {
        return "Direct: Explicit endpoint"
    }
    return "Direct: Endpoint not configured"
}

object DefaultTunnelCatalog {
    val defaultProfile = TunnelProfile(
        id = "default-tunnel",
        name = "My Tunnel",
        host = "edge.example.com",
        port = 443,
        transport = "grpc",
        sourceMode = TunnelSourceMode.ProxyResolver,
        sourceUrl = "https://subscription.example/path",
        serverName = "edge.example.com",
        uuid = "00000000-0000-0000-0000-000000000000",
    )
    val defaultProfiles: List<TunnelProfile> = listOf(defaultProfile)
}
