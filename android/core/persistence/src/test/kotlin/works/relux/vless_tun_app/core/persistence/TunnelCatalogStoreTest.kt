package works.relux.vless_tun_app.core.persistence

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.model.TunnelSourceMode

class TunnelCatalogStoreTest {
    @Test
    fun load_seedsDefaultCatalogWhenFileIsMissing() {
        val tempDir = Files.createTempDirectory("tunnel-catalog-test").toFile()
        val store = TunnelCatalogStore(tempDir.resolve("config/tunnel-catalog.json"))

        val catalog = store.load(defaultCatalog())

        assertEquals(DefaultTunnelCatalog.defaultProfile.id, catalog.selectedProfileId)
        assertTrue(store.storagePath().endsWith("config/tunnel-catalog.json"))
        assertTrue(tempDir.resolve("config/tunnel-catalog.json").exists())
    }

    @Test
    fun saveAndLoad_roundTripsProfilesAndSelection() {
        val tempDir = Files.createTempDirectory("tunnel-catalog-test").toFile()
        val store = TunnelCatalogStore(tempDir.resolve("runtime/catalog.json"))
        val extraProfile = TunnelProfile(
            id = "direct-custom",
            name = "Direct Custom",
            host = "edge.example.net",
            port = 7443,
            transport = "ws",
            sourceMode = TunnelSourceMode.DirectVless,
            sourceUrl = "",
            serverName = "edge.example.net",
            uuid = "11111111-1111-1111-1111-111111111111",
            routeMasks = listOf("ipify.org"),
            bypassMasks = listOf(".api64.ipify.org"),
        )
        val catalog = TunnelCatalog(
            profiles = defaultCatalog().profiles + extraProfile,
            selectedProfileId = extraProfile.id,
        )

        store.save(catalog)
        val loaded = store.load(defaultCatalog())

        assertEquals(extraProfile.id, loaded.selectedProfileId)
        assertEquals(2, loaded.profiles.size)
        assertEquals("Direct Custom", loaded.profiles.last().name)
        assertEquals(listOf("ipify.org"), loaded.profiles.last().routeMasks)
        assertEquals(listOf(".api64.ipify.org"), loaded.profiles.last().bypassMasks)
    }

    private fun defaultCatalog(): TunnelCatalog {
        return TunnelCatalog(
            profiles = DefaultTunnelCatalog.defaultProfiles,
            selectedProfileId = DefaultTunnelCatalog.defaultProfile.id,
        )
    }
}
