package works.relux.vless_tun_app.feature.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.model.TunnelSourceMode

class TunnelHomeStoreTest {
    @Test
    fun saveTunnel_addsAndSelectsNewProfile() {
        val store = buildStore()

        store.dispatch(TunnelHomeAction.AddTunnelClicked)
        store.dispatch(TunnelHomeAction.EditorNameChanged("Lab Tunnel"))
        store.dispatch(TunnelHomeAction.EditorSourceModeChanged(TunnelSourceMode.ProxyResolver))
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
        store.dispatch(TunnelHomeAction.EditorSourceModeChanged(TunnelSourceMode.ProxyResolver))
        store.dispatch(TunnelHomeAction.EditorSourceUrlChanged("https://subscription.example/path"))
        store.dispatch(TunnelHomeAction.SaveTunnelClicked)

        val state = store.state.value
        assertFalse(state.editor.isVisible)
        assertEquals("Source Driven", state.profileName)
        assertEquals("Subscription URL: subscription.example", state.profileSourceSummary)
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
        onConnectRequest: (TunnelProfile) -> Unit = {},
        onCatalogChanged: (List<TunnelProfile>, String?) -> Unit = { _, _ -> },
    ): TunnelHomeStore {
        return TunnelHomeStore(
            initialProfiles = DefaultTunnelCatalog.defaultProfiles,
            renderConfig = { profile ->
                "{\"server\":\"${profile.host.ifBlank { profile.sourceUrl }}\"}"
            },
            onConnectRequest = onConnectRequest,
            onDisconnectRequest = {},
            onCatalogChanged = onCatalogChanged,
        )
    }
}
