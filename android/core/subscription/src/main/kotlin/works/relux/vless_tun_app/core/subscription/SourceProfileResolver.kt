package works.relux.vless_tun_app.core.subscription

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import works.relux.vless_tun_app.core.model.TunnelProfile

class SourceProfileResolver(
    private val fetchText: suspend (String) -> String = ::defaultFetchText,
) {
    suspend fun resolve(profile: TunnelProfile): TunnelProfile {
        val trimmedSource = profile.sourceUrl.trim()
        if (trimmedSource.isBlank()) {
            return requireExplicitProfile(profile)
        }

        return when {
            trimmedSource.startsWith("vless://", ignoreCase = true) -> {
                mergeResolved(profile, parseVlessUri(trimmedSource))
            }
            trimmedSource.startsWith("http://", ignoreCase = true) ||
                trimmedSource.startsWith("https://", ignoreCase = true) -> {
                val payload = fetchText(trimmedSource)
                val normalizedPayload = normalizePayload(payload)
                val resolvedUri = normalizedPayload
                    .lineSequence()
                    .map(String::trim)
                    .firstOrNull { candidate ->
                        candidate.isNotBlank() &&
                            !candidate.startsWith("#") &&
                            !candidate.startsWith("//")
                    }
                    ?: throw IllegalArgumentException("Subscription payload does not contain any VLESS profiles.")
                mergeResolved(profile, parseVlessUri(resolvedUri))
            }
            hasExplicitEndpoint(profile) -> profile
            else -> throw IllegalArgumentException("Unsupported source URL format. Use https://... or vless://...")
        }
    }

    fun resolveInline(profile: TunnelProfile): TunnelProfile? {
        val trimmedSource = profile.sourceUrl.trim()
        return when {
            trimmedSource.startsWith("vless://", ignoreCase = true) -> {
                runCatching { mergeResolved(profile, parseVlessUri(trimmedSource)) }.getOrNull()
            }
            hasExplicitEndpoint(profile) -> profile
            else -> null
        }
    }

    private fun mergeResolved(
        original: TunnelProfile,
        resolved: ResolvedTunnelSource,
    ): TunnelProfile {
        val resolvedSourceUrl = if (resolved.transport.equals("xhttp", ignoreCase = true)) {
            resolved.rawUri
        } else {
            original.sourceUrl
        }
        return original.copy(
            host = resolved.host,
            port = resolved.port,
            transport = resolved.transport,
            sourceUrl = resolvedSourceUrl,
            serverName = resolved.serverName,
            uuid = resolved.uuid,
            security = resolved.security,
            serviceName = resolved.serviceName,
            fingerprint = resolved.fingerprint,
            publicKey = resolved.publicKey,
            shortId = resolved.shortId,
            flow = resolved.flow,
        )
    }

    private fun requireExplicitProfile(profile: TunnelProfile): TunnelProfile {
        if (hasExplicitEndpoint(profile)) {
            return profile
        }
        throw IllegalArgumentException("Tunnel configuration is incomplete. Add a source URL or fill in host, server name, and UUID.")
    }

    private fun hasExplicitEndpoint(profile: TunnelProfile): Boolean {
        return profile.host.isNotBlank() && profile.serverName.isNotBlank() && profile.uuid.isNotBlank()
    }
}

private suspend fun defaultFetchText(url: String): String = withContext(Dispatchers.IO) {
    val connection = (URL(url).openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 15000
        readTimeout = 15000
        setRequestProperty("Accept", "text/plain,application/json,*/*")
        instanceFollowRedirects = true
    }
    try {
        val code = connection.responseCode
        if (code !in 200..299) {
            throw IllegalArgumentException("Subscription request failed with HTTP $code.")
        }
        connection.inputStream.bufferedReader().use { reader -> reader.readText() }
    } finally {
        connection.disconnect()
    }
}

private data class ResolvedTunnelSource(
    val rawUri: String,
    val host: String,
    val port: Int,
    val transport: String,
    val serverName: String,
    val uuid: String,
    val security: String,
    val serviceName: String,
    val fingerprint: String,
    val publicKey: String,
    val shortId: String,
    val flow: String,
)

private fun parseVlessUri(raw: String): ResolvedTunnelSource {
    val parsed = URI(raw)
    if (!parsed.scheme.equals("vless", ignoreCase = true)) {
        throw IllegalArgumentException("Unsupported scheme ${parsed.scheme}.")
    }

    val host = parsed.host ?: throw IllegalArgumentException("Missing host in VLESS URI.")
    val port = if (parsed.port == -1) {
        443
    } else {
        parsed.port
    }
    val userInfo = parsed.rawUserInfo ?: throw IllegalArgumentException("Missing UUID in VLESS URI.")
    val uuid = URLDecoder.decode(userInfo, StandardCharsets.UTF_8)
    val query = decodeQuery(parsed.rawQuery)
    val transport = query["type"] ?: query["network"] ?: "tcp"
    val serverName = query["sni"] ?: query["serverName"] ?: host
    val security = query["security"] ?: ""
    val serviceName = query["serviceName"] ?: query["service_name"] ?: ""
    val fingerprint = query["fp"] ?: query["fingerprint"] ?: ""
    val publicKey = query["pbk"] ?: query["publicKey"] ?: ""
    val shortId = query["sid"] ?: query["shortId"] ?: ""
    val flow = query["flow"] ?: ""

    return ResolvedTunnelSource(
        rawUri = raw.trim(),
        host = host,
        port = port,
        transport = transport,
        serverName = serverName,
        uuid = uuid,
        security = security,
        serviceName = serviceName,
        fingerprint = fingerprint,
        publicKey = publicKey,
        shortId = shortId,
        flow = flow,
    )
}

private fun normalizePayload(rawPayload: String): String {
    val trimmed = rawPayload.trim()
    if (trimmed.isEmpty()) {
        throw IllegalArgumentException("Subscription payload is empty.")
    }
    if (trimmed.contains("://")) {
        return trimmed
    }

    val compact = trimmed.replace(Regex("\\s+"), "")
    val decoders = listOf(
        Base64.getDecoder(),
        Base64.getUrlDecoder(),
    )
    decoders.forEach { decoder ->
        runCatching {
            val decoded = decoder.decode(compact)
            val normalized = decoded.toString(StandardCharsets.UTF_8).trim()
            if (normalized.contains("://")) {
                return normalized
            }
        }
    }

    throw IllegalArgumentException("Unsupported subscription payload format.")
}

private fun decodeQuery(rawQuery: String?): Map<String, String> {
    if (rawQuery.isNullOrBlank()) return emptyMap()
    return rawQuery.split("&")
        .mapNotNull { chunk ->
            if (chunk.isBlank()) return@mapNotNull null
            val pair = chunk.split("=", limit = 2)
            val key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8)
            val value = URLDecoder.decode(pair.getOrElse(1) { "" }, StandardCharsets.UTF_8)
            key to value
        }
        .toMap()
}
