package works.relux.vless_tun_app.platform.xray

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelAppScopeMode
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeBackend

class XrayTunnelConfigRendererTest {
    private val renderer = XrayTunnelConfigRenderer()

    @Test
    fun render_buildsXrayBackendConfigFromInlineXhttpShare() {
        val rendered = renderer.render(
            DefaultTunnelCatalog.defaultProfile.copy(
                sourceUrl = SAMPLE_XHTTP_URI,
                transport = "xhttp",
                routeMasks = listOf("ipify.org"),
                bypassMasks = listOf("api64.ipify.org"),
            ),
        )

        assertEquals(TunnelRuntimeBackend.Xray, rendered.backend)
        assertTrue(rendered.json.contains("\"protocol\":\"tun\""))
        assertTrue(rendered.json.contains("\"network\":\"xhttp\""))
        assertTrue(rendered.json.contains("\"serverName\":\"www.investleaks.pro\""))
        assertTrue(rendered.json.contains("\"publicKey\":\"2CQCGkIWGGDkxqDkb7HhZ_er2hQh6jxlaT-MPZUkLxY\""))
        assertTrue(rendered.json.contains("\"spiderX\":\"/vv42GrP5ApVgcZN\""))
        assertTrue(rendered.json.contains("\"host\":\"investleaks.pro\""))
        assertTrue(rendered.json.contains("\"path\":\"/crypto-news\""))
        assertTrue(rendered.json.contains("\"mode\":\"auto\""))
        assertTrue(rendered.json.contains("\"domain\":[\"domain:api64.ipify.org\"]"))
        assertTrue(rendered.json.contains("\"domain\":[\"domain:ipify.org\"]"))
        assertFalse(rendered.json.contains("France-alexis"))
    }

    @Test
    fun render_rejectsNonXhttpTransport() {
        try {
            renderer.render(
                DefaultTunnelCatalog.defaultProfile.copy(
                    sourceUrl = SAMPLE_GRPC_URI,
                    transport = "grpc",
                ),
            )
            fail("Expected non-xhttp share to be rejected.")
        } catch (error: IllegalArgumentException) {
            assertTrue(error.message.orEmpty().contains("transport 'xhttp'"))
        }
    }

    @Test
    fun render_withOnlyBypassMasksKeepsProxyCatchAll() {
        val rendered = renderer.render(
            DefaultTunnelCatalog.defaultProfile.copy(
                sourceUrl = SAMPLE_XHTTP_URI,
                transport = "xhttp",
                bypassMasks = listOf("api64.ipify.org"),
            ),
        )

        assertTrue(rendered.json.contains("\"outboundTag\":\"proxy\""))
        assertFalse(rendered.json.contains("\"domain\":[\"domain:ipify.org\"]"))
    }

    @Test
    fun render_withBlacklistPackages_setsExcludedAppsInRuntimeManifest() {
        val rendered = renderer.render(
            DefaultTunnelCatalog.defaultProfile.copy(
                sourceUrl = SAMPLE_XHTTP_URI,
                transport = "xhttp",
                appScopeMode = TunnelAppScopeMode.Blacklist,
                appPackages = listOf("works.relux.vless_tun_observer"),
            ),
        )

        assertEquals(TunnelRuntimeBackend.Xray, rendered.backend)
        assertEquals(listOf("works.relux.vless_tun_observer"), rendered.runtimeManifest.excludePackages)
        assertTrue(rendered.runtimeManifest.includePackages.isEmpty())
    }

    private companion object {
        const val SAMPLE_XHTTP_URI =
            "vless://2536e4e4-c6f2-41d8-b2dd-24b72c12872a@213.176.73.234:8443?" +
                "encryption=none&fp=chrome&host=investleaks.pro&mode=auto&path=%2Fcrypto-news&" +
                "pbk=2CQCGkIWGGDkxqDkb7HhZ_er2hQh6jxlaT-MPZUkLxY&security=reality&sid=1f55d194dd059d&" +
                "sni=www.investleaks.pro&spx=%2Fvv42GrP5ApVgcZN&type=xhttp#France-alexis"

        const val SAMPLE_GRPC_URI =
            "vless://22222222-2222-2222-2222-222222222222@resolver-edge.example.net:443?" +
                "security=reality&type=grpc&serviceName=grpcservice&sni=edge.example.net&" +
                "fp=qq&pbk=pubkey&sid=abcd"
    }
}
