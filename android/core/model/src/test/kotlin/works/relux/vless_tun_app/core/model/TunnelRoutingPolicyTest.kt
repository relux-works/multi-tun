package works.relux.vless_tun_app.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelRoutingPolicyTest {
    @Test
    fun normalized_collapsesCoveredMasksAndKeepsBypassOverrides() {
        val normalized = TunnelRoutingPolicy(
            routeMasks = listOf("inside.corp.example", "Corp.Example", "corp.example"),
            bypassMasks = listOf("API64.IPIFY.ORG", ".api64.ipify.org"),
        ).normalized()

        assertEquals(listOf("corp.example"), normalized.routeMasks)
        assertEquals(listOf("api64.ipify.org"), normalized.bypassMasks.map { it.trimStart('.') })
    }

    @Test
    fun normalized_removesRouteMasksCoveredByBypasses() {
        val normalized = TunnelRoutingPolicy(
            routeMasks = listOf("corp.example", "bypass.corp.example"),
            bypassMasks = listOf("bypass.corp.example"),
        ).normalized()

        assertEquals(listOf("corp.example"), normalized.routeMasks)
        assertEquals(listOf("bypass.corp.example"), normalized.bypassMasks.map { it.trimStart('.') })
    }

    @Test
    fun parseSuffixMaskText_acceptsLineAndCommaSeparatedLists() {
        val parsed = parseSuffixMaskText("corp.example,\ninside.corp.example\n.api64.ipify.org")

        assertEquals(listOf("corp.example", ".api64.ipify.org"), parsed)
    }

    @Test
    fun profileRoutingPolicy_reportsAllowListModeWhenRoutesExist() {
        val policy = DefaultTunnelCatalog.defaultProfile.copy(
            routeMasks = listOf("ipify.org"),
        ).routingPolicy()

        assertTrue(policy.usesRouteAllowList)
    }
}
