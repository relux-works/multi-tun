package works.relux.vless_tun_app.core.subscription

import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog

class SourceProfileResolverTest {
    @Test
    fun resolveInline_parsesLiteralVlessUri() {
        val resolver = SourceProfileResolver()
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "vless://11111111-1111-1111-1111-111111111111@edge.example.net:7443?type=ws&sni=cdn.example.net",
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
    fun resolve_rejectsUnsupportedXhttpTransportFromSubscriptionPayload() = runBlocking {
        val vless = "vless://44444444-4444-4444-4444-444444444444@203.0.113.88:8443?encryption=none&fp=chrome&host=investleaks.pro&mode=auto&path=%2Fcrypto-news&pbk=2CQCGkIWGGDkxqDkb7HhZ_er2hQh6jxlaT-MPZUkLxY&security=reality&sid=edda9843e1d0&sni=www.investleaks.pro&spx=%2FOPBnmzHndAthSR4&type=xhttp#France-alexis"
        val payload = Base64.getEncoder().encodeToString(vless.toByteArray(StandardCharsets.UTF_8))
        val resolver = SourceProfileResolver(fetchText = { payload })
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceUrl = "https://203.0.113.88:7654/freedom/example",
            host = "",
            serverName = "",
            uuid = "",
        )

        try {
            resolver.resolve(profile)
            fail("Expected xhttp payload to be rejected.")
        } catch (error: IllegalArgumentException) {
            assertTrue(error.message.orEmpty().contains("xhttp"))
            assertTrue(error.message.orEmpty().contains("Android runtime"))
        }
    }
}
