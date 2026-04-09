package works.relux.vless_tun_app.core.model

import java.net.URI

enum class TunnelSourceMode(
    val title: String,
    val subtitle: String,
) {
    ProxyResolver(
        title = "Subscription",
        subtitle = "Fetch and resolve your subscription URL on every connect.",
    ),
    DirectVless(
        title = "Direct VLESS",
        subtitle = "Paste one direct VLESS URI with no subscription fetch.",
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

fun TunnelProfile.endpoint(): String = when {
    host.isNotBlank() -> "$host:$port"
    sourceUrl.isNotBlank() -> "Resolved on connect"
    else -> "Endpoint not configured"
}

fun TunnelProfile.transportLabel(): String = when {
    transport.isNotBlank() -> transport.uppercase()
    sourceUrl.isNotBlank() -> "AUTO"
    else -> "AUTO"
}

fun TunnelProfile.sourceSummary(): String = when (sourceMode) {
    TunnelSourceMode.ProxyResolver -> sourceUrl.toResolverSummary()
    TunnelSourceMode.DirectVless -> sourceUrl.toDirectSummary(serverName)
}

private fun String.toResolverSummary(): String {
    val trimmed = trim()
    if (trimmed.isBlank()) {
        return "Subscription URL not configured"
    }
    val parsed = runCatching { URI(trimmed) }.getOrNull()
    val scheme = parsed?.scheme?.lowercase()
    val host = parsed?.host?.takeIf { it.isNotBlank() }
    return when (scheme) {
        "http", "https" -> "Subscription URL: ${host ?: "configured"}"
        "vless" -> "Subscription: inline VLESS URI"
        else -> "Subscription source configured"
    }
}

private fun String.toDirectSummary(serverName: String): String {
    val trimmed = trim()
    if (trimmed.startsWith("vless://", ignoreCase = true)) {
        return "Direct VLESS URI configured"
    }
    if (serverName.isNotBlank()) {
        return "Manual endpoint configured"
    }
    return "Direct VLESS URI not configured"
}

object DefaultTunnelCatalog {
    val defaultProfile = TunnelProfile(
        id = "default-tunnel",
        name = "My Tunnel",
        host = "",
        port = 443,
        transport = "",
        sourceMode = TunnelSourceMode.ProxyResolver,
        sourceUrl = "https://subscription.example/path",
        serverName = "",
        uuid = "",
    )
    val defaultProfiles: List<TunnelProfile> = listOf(defaultProfile)
}
