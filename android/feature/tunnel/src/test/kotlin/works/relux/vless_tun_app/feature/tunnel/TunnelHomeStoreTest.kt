package works.relux.vless_tun_app.feature.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelAppScopeMode
import works.relux.vless_tun_app.core.model.TunnelProfile

class TunnelHomeStoreTest {
    @Test
    fun saveTunnel_addsAndSelectsNewProfile() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorNameChanged("Lab Tunnel"))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("https://lab.vpn.example/bootstrap"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val state = store.state.value
        assertEquals("Lab Tunnel", state.profileName)
        assertEquals(2, state.profiles.size)
        assertFalse(state.editor.isVisible)
        assertEquals("Subscription URL: lab.vpn.example", state.profileSourceSummary)
        assertEquals("Resolved on connect", state.profileEndpoint)
    }

    @Test
    fun addTunnel_prefersSourceFirstEditorFlow() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)

        val editor = store.state.value.editor
        assertTrue(editor.isVisible)
        assertEquals("https://subscription.example/path", editor.sourceUrl)
        assertFalse(editor.showManualEndpointFields)
    }

    @Test
    fun clearingSourceUrl_forcesManualEndpointFieldsVisible() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged(""))

        val editor = store.state.value.editor
        assertEquals("", editor.sourceUrl)
        assertTrue(editor.showManualEndpointFields)
    }

    @Test
    fun primaryClick_connectsSelectedProfile() {
        var connectedProfile: TunnelProfile? = null
        val store = buildStore(
            onConnectRequest = { connectedProfile = it },
        )

        val defaultId = DefaultTunnelCatalog.defaultProfile.id
        store.dispatch(TunnelHomeAction.SelectTunnelClicked(defaultId))
        store.dispatch(TunnelHomeAction.PrimaryButtonClicked)

        assertNotNull(connectedProfile)
        assertEquals(defaultId, connectedProfile?.id)
    }

    @Test
    fun selectAndSave_emitCatalogPersistence() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        var persistedSelection: String? = null
        val store = buildStore(
            onCatalogChanged = { profiles, selectedProfileId ->
                persistedProfiles = profiles
                persistedSelection = selectedProfileId
            },
        )

        store.dispatch(TunnelHomeAction.SelectTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("https://subscription.example/updated"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        assertEquals(DefaultTunnelCatalog.defaultProfile.id, persistedSelection)
        assertEquals(1, persistedProfiles.size)
        assertEquals("https://subscription.example/updated", persistedProfiles.first().sourceUrl)
    }

    @Test
    fun saveTunnel_allowsSourceOnlyConfigWithoutExplicitEndpoint() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorNameChanged("Source Driven"))
        store.dispatch(TunnelHomeAction.EditorHostChanged(""))
        store.dispatch(TunnelHomeAction.EditorServerNameChanged(""))
        store.dispatch(TunnelHomeAction.EditorUuidChanged(""))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("https://subscription.example/path"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val state = store.state.value
        assertFalse(state.editor.isVisible)
        assertEquals("Source Driven", state.profileName)
        assertEquals("Subscription URL: subscription.example", state.profileSourceSummary)
        assertEquals("Resolved on connect", state.profileEndpoint)
    }

    @Test
    fun saveTunnel_autoDetectsInlineVlessSourceSummary() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorNameChanged("Inline XHTTP"))
        store.dispatch(
            TunnelHomeAction.EditorSourceUrlChanged(
                "vless://2536e4e4-c6f2-41d8-b2dd-24b72c12872a@213.176.73.234:8443?encryption=none&fp=chrome&host=investleaks.pro&mode=auto&path=%2Fcrypto-news&pbk=2CQCGkIWGGDkxqDkb7HhZ_er2hQh6jxlaT-MPZUkLxY&security=reality&sid=1f55d194dd059d&sni=www.investleaks.pro&type=xhttp#France-alexis",
            ),
        )
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val state = store.state.value
        assertEquals("Inline VLESS URI: 213.176.73.234", state.profileSourceSummary)
        assertEquals("Resolved on connect", state.profileEndpoint)
    }

    @Test
    fun saveTunnel_withSourceUrl_clearsSampleManualFields() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        val store = buildStore(
            onCatalogChanged = { profiles, _ ->
                persistedProfiles = profiles
            },
        )

        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("https://vpn.example.com/subscription"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val persisted = persistedProfiles.single()
        assertEquals("", persisted.host)
        assertEquals("", persisted.serverName)
        assertEquals("", persisted.uuid)
        assertEquals("", persisted.transport)
    }

    @Test
    fun saveTunnel_manualEndpointDefaultsToTls() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        val store = buildStore(
            onCatalogChanged = { profiles, _ ->
                persistedProfiles = profiles
            },
        )

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorNameChanged("Manual TLS"))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged(""))
        store.dispatch(TunnelHomeAction.EditorHostChanged("edge.example.net"))
        store.dispatch(TunnelHomeAction.EditorServerNameChanged("cdn.example.net"))
        store.dispatch(TunnelHomeAction.EditorUuidChanged("11111111-1111-1111-1111-111111111111"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val persisted = persistedProfiles.last()
        assertEquals("tls", persisted.security)
    }

    @Test
    fun saveTunnel_rejectsHttpSourceUrl() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("http://subscription.example/path"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        assertEquals(
            "Source URL must use https:// or be a vless:// URI.",
            store.state.value.editor.validationError,
        )
    }

    @Test
    fun saveTunnel_normalizesRouteAndBypassMasks() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        val store = buildStore(
            onCatalogChanged = { profiles, _ ->
                persistedProfiles = profiles
            },
        )

        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.EditorRouteMasksChanged("inside.corp.example\nCorp.Example\ncorp.example"))
        store.dispatch(TunnelHomeAction.EditorBypassMasksChanged(".API64.IPIFY.ORG\napi64.ipify.org"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val persisted = persistedProfiles.single()
        assertEquals(listOf("corp.example"), persisted.routeMasks)
        assertEquals(listOf(".api64.ipify.org"), persisted.bypassMasks)
    }

    @Test
    fun editingTunnel_reloadsNormalizedRouteAndBypassMasks() {
        val seededProfile = DefaultTunnelCatalog.defaultProfile.copy(
            routeMasks = listOf("corp.example"),
            bypassMasks = listOf(".api64.ipify.org"),
        )
        val store = buildStore(initialProfiles = listOf(seededProfile))

        store.dispatch(TunnelHomeAction.EditTunnelClicked(seededProfile.id))

        val editor = store.state.value.editor
        assertEquals("corp.example", editor.routeMasksText)
        assertEquals(".api64.ipify.org", editor.bypassMasksText)
    }

    @Test
    fun saveTunnel_persistsAppScopeModeAndPackages() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        val store = buildStore(
            onCatalogChanged = { profiles, _ ->
                persistedProfiles = profiles
            },
        )

        store.syncInstalledApps(
            listOf(
                TunnelInstalledApp(packageName = "works.relux.vless_tun_observer", label = "Tunnel Observer"),
            ),
        )
        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.EditorAppScopeModeChanged(TunnelAppScopeMode.Whitelist))
        store.dispatch(TunnelHomeAction.EditorAppSelectionToggled("works.relux.vless_tun_observer"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val persisted = persistedProfiles.single()
        assertEquals(TunnelAppScopeMode.Whitelist, persisted.appScopeMode)
        assertEquals(listOf("works.relux.vless_tun_observer"), persisted.appPackages)
    }

    @Test
    fun deleteEditedTunnel_removesProfileAndSelectsFallback() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        var persistedSelection: String? = null
        val secondaryProfile = DefaultTunnelCatalog.defaultProfile.copy(
            id = "backup-profile",
            name = "Backup",
            sourceUrl = "https://backup.example/path",
        )
        val store = buildStore(
            initialProfiles = listOf(DefaultTunnelCatalog.defaultProfile, secondaryProfile),
            onCatalogChanged = { profiles, selectedProfileId ->
                persistedProfiles = profiles
                persistedSelection = selectedProfileId
            },
        )

        store.dispatch(TunnelHomeAction.SelectTunnelClicked(secondaryProfile.id))
        store.dispatch(TunnelHomeAction.EditTunnelClicked(secondaryProfile.id))
        store.dispatch(TunnelHomeAction.DeleteEditedTunnelClicked)

        val state = store.state.value
        assertFalse(state.editor.isVisible)
        assertEquals(1, state.profiles.size)
        assertEquals(DefaultTunnelCatalog.defaultProfile.id, state.selectedProfileId)
        assertEquals(DefaultTunnelCatalog.defaultProfile.id, persistedSelection)
        assertEquals(listOf(DefaultTunnelCatalog.defaultProfile.id), persistedProfiles.map(TunnelProfile::id))
    }

    @Test
    fun deleteEditedTunnel_allowsEmptyCatalog() {
        var persistedProfiles: List<TunnelProfile> = emptyList()
        val store = buildStore(
            onCatalogChanged = { profiles, _ ->
                persistedProfiles = profiles
            },
        )

        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.dispatch(TunnelHomeAction.DeleteEditedTunnelClicked)

        val state = store.state.value
        assertTrue(state.profiles.isEmpty())
        assertEquals("No tunnels configured", state.profileName)
        assertEquals("Tunnel deleted. Add a new tunnel to continue.", state.detail)
        assertTrue(persistedProfiles.isEmpty())
    }

    @Test
    fun syncInstalledApps_populatesVisibleEditorPickerData() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.EditTunnelClicked(DefaultTunnelCatalog.defaultProfile.id))
        store.syncInstalledApps(
            listOf(
                TunnelInstalledApp(packageName = "works.relux.vless_tun_observer", label = "Tunnel Observer"),
            ),
        )
        store.dispatch(TunnelHomeAction.EditorOpenAppPickerClicked)

        val editor = store.state.value.editor
        assertFalse(editor.isLoadingInstalledApps)
        assertTrue(editor.isAppPickerVisible)
        assertEquals(1, editor.installedApps.size)
        assertEquals("Tunnel Observer", editor.installedApps.single().label)
    }

    @Test
    fun egressObservations_trackDirectAndTunnelSnapshots() {
        val store = buildStore()

        store.onEgressRefreshStarted()
        assertTrue(store.state.value.egress.isLoading)

        store.onEgressObserved(
            phase = works.relux.vless_tun_app.core.runtime.TunnelPhase.Disconnected,
            observation = EgressObservation(ip = "203.0.113.10", country = "Russia", countryCode = "RU"),
        )
        store.onEgressObserved(
            phase = works.relux.vless_tun_app.core.runtime.TunnelPhase.Connected,
            observation = EgressObservation(ip = "198.51.100.20", country = "Finland", countryCode = "FI"),
        )

        val egress = store.state.value.egress
        assertEquals("203.0.113.10", egress.directObservation?.ip)
        assertEquals("198.51.100.20", egress.tunneledObservation?.ip)
        assertNotEquals(egress.directObservation?.ip, egress.tunneledObservation?.ip)
        assertEquals("Egress changed after connect.", egress.comparisonLabel)
    }

    private fun buildStore(
        initialProfiles: List<TunnelProfile> = DefaultTunnelCatalog.defaultProfiles,
        onConnectRequest: (TunnelProfile) -> Unit = {},
        onCatalogChanged: (List<TunnelProfile>, String?) -> Unit = { _, _ -> },
    ): TunnelHomeStore {
        return TunnelHomeStore(
            initialProfiles = initialProfiles,
            renderConfig = { profile ->
                "{\"server\":\"${profile.host.ifBlank { profile.sourceUrl }}\"}"
            },
            onConnectRequest = onConnectRequest,
            onDisconnectRequest = {},
            onCatalogChanged = onCatalogChanged,
        )
    }
}
