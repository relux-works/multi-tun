package works.relux.vless_tun_app.core.model

import java.net.URI

enum class TunnelSourceKind {
    Subscription,
    InlineVless,
    ManualEndpoint,
    Unconfigured,
}

data class TunnelProfile(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val transport: String,
    val sourceUrl: String,
    val serverName: String,
    val uuid: String,
    val security: String = "",
    val serviceName: String = "",
    val fingerprint: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val flow: String = "",
    val routeMasks: List<String> = emptyList(),
    val bypassMasks: List<String> = emptyList(),
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

fun TunnelProfile.sourceKind(): TunnelSourceKind {
    val trimmedSource = sourceUrl.trim()
    return when {
        trimmedSource.startsWith("http://", ignoreCase = true) ||
            trimmedSource.startsWith("https://", ignoreCase = true) -> TunnelSourceKind.Subscription
        trimmedSource.startsWith("vless://", ignoreCase = true) -> TunnelSourceKind.InlineVless
        host.isNotBlank() && serverName.isNotBlank() && uuid.isNotBlank() -> TunnelSourceKind.ManualEndpoint
        else -> TunnelSourceKind.Unconfigured
    }
}

fun TunnelProfile.sourceSummary(): String = when (sourceKind()) {
    TunnelSourceKind.Subscription -> sourceUrl.toResolverSummary()
    TunnelSourceKind.InlineVless -> sourceUrl.toInlineSummary(serverName)
    TunnelSourceKind.ManualEndpoint -> "Manual endpoint configured"
    TunnelSourceKind.Unconfigured -> "Connection source not configured"
}

fun TunnelProfile.routingPolicy(): TunnelRoutingPolicy {
    return TunnelRoutingPolicy(
        routeMasks = routeMasks,
        bypassMasks = bypassMasks,
    ).normalized()
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

private fun String.toInlineSummary(serverName: String): String {
    val trimmed = trim()
    if (!trimmed.startsWith("vless://", ignoreCase = true)) {
        return if (serverName.isNotBlank()) {
            "Inline VLESS URI: $serverName"
        } else {
            "Inline VLESS URI configured"
        }
    }
    val parsed = runCatching { URI(trimmed) }.getOrNull()
    val host = parsed?.host?.takeIf { it.isNotBlank() } ?: serverName.takeIf { it.isNotBlank() }
    return if (host != null) {
        "Inline VLESS URI: $host"
    } else {
        "Inline VLESS URI configured"
    }
}

object DefaultTunnelCatalog {
    val defaultProfile = TunnelProfile(
        id = "default-tunnel",
        name = "My Tunnel",
        host = "",
        port = 443,
        transport = "",
        sourceUrl = "https://subscription.example/path",
        serverName = "",
        uuid = "",
    )
    val defaultProfiles: List<TunnelProfile> = listOf(defaultProfile)
}
