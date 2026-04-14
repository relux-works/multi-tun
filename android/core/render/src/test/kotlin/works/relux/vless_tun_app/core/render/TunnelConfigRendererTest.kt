package works.relux.vless_tun_app.core.render

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelAppScopeMode

class TunnelConfigRendererTest {
    @Test
    fun render_keeps_tun_only_shape() {
        val rendered = TunnelConfigRenderer().render(DefaultTunnelCatalog.defaultProfile)

        assertTrue(rendered.json.contains("\"type\": \"tun\""))
        assertTrue(rendered.json.contains("\"uuid\":"))
        assertTrue(rendered.json.contains("\"dns-bootstrap\""))
        assertTrue(rendered.json.contains("\"final\": \"proxy\""))
        assertFalse(rendered.runtimeManifest.isMockDataPlane)
        assertEquals("0.0.0.0", rendered.runtimeManifest.routes.first().address)
        assertFalse(rendered.json.contains("\"listen\""))
        assertFalse(rendered.json.contains("127.0.0.1"))
        assertFalse(rendered.json.contains("[::1]"))
        assertFalse(rendered.json.contains("\"socks\""))
        assertFalse(rendered.json.contains("\"mixed\""))
        assertFalse(rendered.json.contains("\"http\""))
        assertFalse(rendered.json.contains("\"experimental\""))
    }

    @Test
    fun render_withBypassMasks_keepsFullTunnelAndAddsDirectExceptions() {
        val rendered = TunnelConfigRenderer().render(
            DefaultTunnelCatalog.defaultProfile.copy(
                bypassMasks = listOf(".api64.ipify.org"),
            ),
        )

        assertTrue(rendered.json.contains("\"tag\": \"routing-bypass\""))
        assertTrue(rendered.json.contains("\"api64.ipify.org\""))
        assertTrue(rendered.json.contains("\"server\": \"dns-direct\""))
        assertTrue(rendered.json.contains("\"final\": \"proxy\""))
    }

    @Test
    fun render_withRouteMasks_switchesDefaultTrafficToDirect() {
        val rendered = TunnelConfigRenderer().render(
            DefaultTunnelCatalog.defaultProfile.copy(
                routeMasks = listOf("ipify.org"),
                bypassMasks = listOf("api64.ipify.org"),
            ),
        )

        assertTrue(rendered.json.contains("\"tag\": \"routing-proxy\""))
        assertTrue(rendered.json.contains("\"tag\": \"routing-bypass\""))
        assertTrue(rendered.json.contains("\"domain_resolver\": \"dns-direct\""))
        assertTrue(rendered.json.contains("\"server\": \"dns-direct\""))
        assertTrue(rendered.json.contains("\"server\": \"dns-proxy\""))
        assertTrue(rendered.json.contains("\"final\": \"direct\""))
    }

    @Test
    fun render_withWhitelistPackages_setsAllowedAppsInRuntimeManifest() {
        val rendered = TunnelConfigRenderer().render(
            DefaultTunnelCatalog.defaultProfile.copy(
                appScopeMode = TunnelAppScopeMode.Whitelist,
                appPackages = listOf("works.relux.vless_tun_observer"),
            ),
        )

        assertEquals(listOf("works.relux.vless_tun_observer"), rendered.runtimeManifest.includePackages)
        assertTrue(rendered.runtimeManifest.excludePackages.isEmpty())
        assertTrue(rendered.json.contains("\"include_package\":[\"works.relux.vless_tun_observer\"]"))
    }

    @Test
    fun render_withBlacklistPackages_setsExcludedAppsInTunInbound() {
        val rendered = TunnelConfigRenderer().render(
            DefaultTunnelCatalog.defaultProfile.copy(
                appScopeMode = TunnelAppScopeMode.Blacklist,
                appPackages = listOf("works.relux.vless_tun_observer"),
            ),
        )

        assertEquals(listOf("works.relux.vless_tun_observer"), rendered.runtimeManifest.excludePackages)
        assertTrue(rendered.runtimeManifest.includePackages.isEmpty())
        assertTrue(rendered.json.contains("\"exclude_package\":[\"works.relux.vless_tun_observer\"]"))
    }
}
