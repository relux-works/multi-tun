package works.relux.vless_tun_app.core.subscription

import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog

class SourceProfileResolverTest {
    @Test
    fun resolveInline_parsesLiteralVlessUri() {
        val resolver = SourceProfileResolver()
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "vless://11111111-1111-1111-1111-111111111111@edge.example.net:7443?security=tls&type=ws&sni=cdn.example.net",
            host = "",
            serverName = "",
            uuid = "",
        )

        val resolved = resolver.resolveInline(profile)

        requireNotNull(resolved)
        assertEquals("edge.example.net", resolved.host)
        assertEquals(7443, resolved.port)
        assertEquals("ws", resolved.transport)
        assertEquals("cdn.example.net", resolved.serverName)
        assertEquals("11111111-1111-1111-1111-111111111111", resolved.uuid)
        assertEquals("tls", resolved.security)
    }

    @Test
    fun resolveInline_rejectsLiteralVlessUriWithoutSecureTransport() {
        val resolver = SourceProfileResolver()
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "vless://11111111-1111-1111-1111-111111111111@edge.example.net:7443?type=ws&sni=cdn.example.net",
            host = "",
            serverName = "",
            uuid = "",
        )

        val resolved = resolver.resolveInline(profile)

        assertNull(resolved)
    }

    @Test
    fun resolve_fetchesAndParsesBase64SubscriptionPayload() = runBlocking {
        val vless = "vless://22222222-2222-2222-2222-222222222222@resolver-edge.example.net:443?security=reality&type=grpc&serviceName=grpcservice&sni=edge.example.net&fp=qq&pbk=pubkey&sid=abcd"
        val payload = Base64.getEncoder().encodeToString(vless.toByteArray(StandardCharsets.UTF_8))
        val resolver = SourceProfileResolver(fetchText = { payload })
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "https://subscription.example/path",
            host = "",
            serverName = "",
            uuid = "",
        )

        val resolved = resolver.resolve(profile)

        assertEquals("resolver-edge.example.net", resolved.host)
        assertEquals(443, resolved.port)
        assertEquals("grpc", resolved.transport)
        assertEquals("edge.example.net", resolved.serverName)
        assertEquals("22222222-2222-2222-2222-222222222222", resolved.uuid)
        assertEquals("reality", resolved.security)
        assertEquals("grpcservice", resolved.serviceName)
        assertEquals("qq", resolved.fingerprint)
        assertEquals("pubkey", resolved.publicKey)
        assertEquals("abcd", resolved.shortId)
    }

    @Test
    fun resolve_acceptsXhttpTransportFromSubscriptionPayloadAndKeepsResolvedShareLink() = runBlocking {
        val vless = "vless://2536e4e4-c6f2-41d8-b2dd-24b72c12872a@213.176.73.234:8443?encryption=none&fp=chrome&host=investleaks.pro&mode=auto&path=%2Fcrypto-news&pbk=2CQCGkIWGGDkxqDkb7HhZ_er2hQh6jxlaT-MPZUkLxY&security=reality&sid=edda9843e1d0&sni=www.investleaks.pro&spx=%2FOPBnmzHndAthSR4&type=xhttp#France-alexis"
        val payload = Base64.getEncoder().encodeToString(vless.toByteArray(StandardCharsets.UTF_8))
        val resolver = SourceProfileResolver(fetchText = { payload })
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "https://213.176.73.234:7654/freedom/example",
            host = "",
            serverName = "",
            uuid = "",
        )

        val resolved = resolver.resolve(profile)

        assertEquals("213.176.73.234", resolved.host)
        assertEquals(8443, resolved.port)
        assertEquals("xhttp", resolved.transport)
        assertEquals("www.investleaks.pro", resolved.serverName)
        assertEquals("2536e4e4-c6f2-41d8-b2dd-24b72c12872a", resolved.uuid)
        assertEquals("reality", resolved.security)
        assertTrue(resolved.sourceUrl.startsWith("vless://2536e4e4-c6f2-41d8-b2dd-24b72c12872a@213.176.73.234:8443"))
    }

    @Test
    fun resolve_rejectsHttpSubscriptionUrl() = runBlocking {
        val resolver = SourceProfileResolver(fetchText = { error("fetchText should not be called for http:// sources") })
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "http://subscription.example/path",
            host = "",
            serverName = "",
            uuid = "",
        )

        try {
            resolver.resolve(profile)
            error("Expected http:// source to be rejected.")
        } catch (error: IllegalArgumentException) {
            assertEquals("Subscription URL must use https://.", error.message)
        }
    }

    @Test
    fun resolve_defaultsExplicitManualProfileToTls() = runBlocking {
        val resolver = SourceProfileResolver()
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "",
            host = "edge.example.net",
            port = 443,
            transport = "grpc",
            serverName = "cdn.example.net",
            uuid = "11111111-1111-1111-1111-111111111111",
            security = "",
        )

        val resolved = resolver.resolve(profile)

        assertEquals("tls", resolved.security)
    }
}
