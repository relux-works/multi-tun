package works.relux.vless_tun_app.core.subscription

import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelSourceMode

class SourceProfileResolverTest {
    @Test
    fun resolveInline_parsesLiteralVlessUri() {
        val resolver = SourceProfileResolver()
        val profile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceMode = TunnelSourceMode.DirectVless,
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
}
