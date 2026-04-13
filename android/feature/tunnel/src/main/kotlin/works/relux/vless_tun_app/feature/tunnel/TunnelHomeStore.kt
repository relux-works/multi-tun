package works.relux.vless_tun_app.feature.tunnel

import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import works.relux.vless_tun_app.core.mvi.MviStore
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.model.TunnelSourceMode
import works.relux.vless_tun_app.core.model.endpoint
import works.relux.vless_tun_app.core.model.parseSuffixMaskText
import works.relux.vless_tun_app.core.model.routeMasksText
import works.relux.vless_tun_app.core.model.bypassMasksText
import works.relux.vless_tun_app.core.model.routingPolicy
import works.relux.vless_tun_app.core.model.sourceSummary
import works.relux.vless_tun_app.core.model.transportLabel
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot

sealed interface TunnelHomeAction {
    data object PrimaryButtonClicked : TunnelHomeAction
    data object RefreshEgressClicked : TunnelHomeAction
    data object AddTunnelClicked : TunnelHomeAction
    data class SelectTunnelClicked(val profileId: String) : TunnelHomeAction
    data class EditTunnelClicked(val profileId: String) : TunnelHomeAction
    data object DismissEditorClicked : TunnelHomeAction
    data class EditorNameChanged(val value: String) : TunnelHomeAction
    data class EditorHostChanged(val value: String) : TunnelHomeAction
    data class EditorPortChanged(val value: String) : TunnelHomeAction
    data class EditorTransportChanged(val value: String) : TunnelHomeAction
    data class EditorSourceModeChanged(val value: TunnelSourceMode) : TunnelHomeAction
    data class EditorSourceUrlChanged(val value: String) : TunnelHomeAction
    data class EditorServerNameChanged(val value: String) : TunnelHomeAction
    data class EditorUuidChanged(val value: String) : TunnelHomeAction
    data class EditorRouteMasksChanged(val value: String) : TunnelHomeAction
    data class EditorBypassMasksChanged(val value: String) : TunnelHomeAction
    data object SaveTunnelClicked : TunnelHomeAction
}

data class TunnelListItemState(
    val id: String,
    val name: String,
    val endpoint: String,
    val sourceSummary: String,
    val transport: String,
    val isSelected: Boolean,
)

enum class TunnelEditorMode {
    Create,
    Edit,
}

data class TunnelEditorState(
    val isVisible: Boolean = false,
    val mode: TunnelEditorMode = TunnelEditorMode.Create,
    val profileId: String? = null,
    val name: String = "",
    val host: String = "",
    val port: String = "443",
    val transport: String = "grpc",
    val sourceMode: TunnelSourceMode = TunnelSourceMode.ProxyResolver,
    val sourceUrl: String = "",
    val serverName: String = "",
    val uuid: String = "",
    val routeMasksText: String = "",
    val bypassMasksText: String = "",
    val validationError: String? = null,
) {
    val title: String
        get() = if (mode == TunnelEditorMode.Create) "Add Tunnel" else "Edit Tunnel"

    val showManualEndpointFields: Boolean
        get() = sourceUrl.isBlank()
}

data class EgressObservation(
    val ip: String,
    val country: String,
    val countryCode: String,
) {
    fun summary(): String = buildString {
        append(ip)
        if (country.isNotBlank()) {
            append(" · ")
            append(country)
            if (countryCode.isNotBlank()) {
                append(" (")
                append(countryCode)
                append(')')
            }
        }
    }
}

data class TunnelEgressState(
    val isLoading: Boolean = false,
    val directObservation: EgressObservation? = null,
    val tunneledObservation: EgressObservation? = null,
    val lastModeLabel: String = "No egress check yet.",
    val error: String? = null,
) {
    val comparisonLabel: String
        get() {
            val direct = directObservation
            val tunneled = tunneledObservation
            if (direct == null || tunneled == null) {
                return "Capture direct egress first, then connect and capture tunneled egress."
            }
            return if (direct.ip != tunneled.ip || direct.countryCode != tunneled.countryCode) {
                "Egress changed after connect."
            } else {
                "Egress did not change yet."
            }
        }
}

data class TunnelHomeState(
    val profiles: List<TunnelListItemState>,
    val selectedProfileId: String?,
    val profileName: String,
    val profileEndpoint: String,
    val profileSourceSummary: String,
    val phase: TunnelPhase,
    val detail: String,
    val configPreview: String,
    val requiresPermission: Boolean,
    val editor: TunnelEditorState,
    val egress: TunnelEgressState,
) {
    val primaryButtonLabel: String
        get() = if (phase == TunnelPhase.Connected || phase == TunnelPhase.Connecting) {
            "Disconnect"
        } else {
            "Connect"
        }
}

class TunnelHomeStore(
    initialProfiles: List<TunnelProfile>,
    initialSelectedProfileId: String? = initialProfiles.firstOrNull()?.id,
    private val renderConfig: (TunnelProfile) -> String,
    private val onConnectRequest: (TunnelProfile) -> Unit,
    private val onDisconnectRequest: () -> Unit,
    private val onRefreshEgressRequest: (TunnelPhase) -> Unit = {},
    private val onCatalogChanged: (List<TunnelProfile>, String?) -> Unit = { _, _ -> },
) : MviStore<TunnelHomeState, TunnelHomeAction> {
    private var profiles: List<TunnelProfile> = initialProfiles
    private var egressState = TunnelEgressState()
    private var selectedProfileId: String? = initialSelectedProfileId
        ?.takeIf { selectedId -> initialProfiles.any { it.id == selectedId } }
        ?: initialProfiles.firstOrNull()?.id
    private val stateFlow = MutableStateFlow(
        buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = TunnelPhase.Disconnected,
            detail = "Edit the seeded tunnel profile, replace the placeholders with your own subscription or direct VLESS endpoint, then connect with the TUN-only runtime.",
            requiresPermission = false,
            editor = TunnelEditorState(),
            egress = egressState,
        ),
    )

    override val state: StateFlow<TunnelHomeState> = stateFlow.asStateFlow()

    override fun dispatch(action: TunnelHomeAction) {
        when (action) {
            TunnelHomeAction.PrimaryButtonClicked -> handlePrimaryClick()
            TunnelHomeAction.RefreshEgressClicked -> handleRefreshEgress()
            TunnelHomeAction.AddTunnelClicked -> openEditor(newEditor())
            is TunnelHomeAction.SelectTunnelClicked -> selectProfile(action.profileId)
            is TunnelHomeAction.EditTunnelClicked -> {
                findProfile(action.profileId)?.let { openEditor(editorFor(it)) }
            }
            TunnelHomeAction.DismissEditorClicked -> closeEditor()
            is TunnelHomeAction.EditorNameChanged -> updateEditor { copy(name = action.value, validationError = null) }
            is TunnelHomeAction.EditorHostChanged -> updateEditor { copy(host = action.value, validationError = null) }
            is TunnelHomeAction.EditorPortChanged -> updateEditor { copy(port = action.value, validationError = null) }
            is TunnelHomeAction.EditorTransportChanged -> updateEditor { copy(transport = action.value, validationError = null) }
            is TunnelHomeAction.EditorSourceModeChanged -> updateEditor {
                copy(
                    sourceMode = action.value,
                    validationError = null,
                )
            }
            is TunnelHomeAction.EditorSourceUrlChanged -> updateEditor {
                copy(
                    sourceUrl = action.value,
                    validationError = null,
                )
            }
            is TunnelHomeAction.EditorServerNameChanged -> updateEditor { copy(serverName = action.value, validationError = null) }
            is TunnelHomeAction.EditorUuidChanged -> updateEditor { copy(uuid = action.value, validationError = null) }
            is TunnelHomeAction.EditorRouteMasksChanged -> updateEditor { copy(routeMasksText = action.value, validationError = null) }
            is TunnelHomeAction.EditorBypassMasksChanged -> updateEditor { copy(bypassMasksText = action.value, validationError = null) }
            TunnelHomeAction.SaveTunnelClicked -> saveEditor()
        }
    }

    fun syncRuntime(snapshot: TunnelRuntimeSnapshot) {
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = snapshot.phase,
            detail = snapshot.detail,
            requiresPermission = snapshot.phase == TunnelPhase.PermissionRequired,
            editor = stateFlow.value.editor,
            egress = egressState,
        )
    }

    fun onPermissionRequired() {
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = TunnelPhase.PermissionRequired,
            detail = "VPN consent is required before the tunnel can start.",
            requiresPermission = true,
            editor = stateFlow.value.editor,
            egress = egressState,
        )
    }

    fun onPermissionDenied() {
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = TunnelPhase.Disconnected,
            detail = "VPN consent was denied. Tunnel stayed offline.",
            requiresPermission = false,
            editor = stateFlow.value.editor,
            egress = egressState,
        )
    }

    fun onConnectFailed(detail: String) {
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = TunnelPhase.Error,
            detail = detail,
            requiresPermission = false,
            editor = stateFlow.value.editor,
            egress = egressState,
        )
    }

    fun onEgressRefreshStarted() {
        egressState = egressState.copy(
            isLoading = true,
            lastModeLabel = when (stateFlow.value.phase) {
                TunnelPhase.Connected -> "Checking tunneled egress..."
                else -> "Checking direct egress..."
            },
            error = null,
        )
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = current.editor,
            egress = egressState,
        )
    }

    fun onEgressObserved(
        phase: TunnelPhase,
        observation: EgressObservation,
    ) {
        egressState = if (phase == TunnelPhase.Connected) {
            egressState.copy(
                isLoading = false,
                tunneledObservation = observation,
                lastModeLabel = "Last check: tunneled egress",
                error = null,
            )
        } else {
            egressState.copy(
                isLoading = false,
                directObservation = observation,
                lastModeLabel = "Last check: direct egress",
                error = null,
            )
        }
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = current.editor,
            egress = egressState,
        )
    }

    fun onEgressRefreshFailed(message: String) {
        egressState = egressState.copy(
            isLoading = false,
            error = message,
        )
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = current.editor,
            egress = egressState,
        )
    }

    private fun handlePrimaryClick() {
        val current = stateFlow.value
        if (current.phase == TunnelPhase.Connected || current.phase == TunnelPhase.Connecting) {
            onDisconnectRequest()
            return
        }
        selectedProfile()?.let(onConnectRequest)
    }

    private fun handleRefreshEgress() {
        val phase = stateFlow.value.phase
        if (phase == TunnelPhase.Connecting || phase == TunnelPhase.Disconnecting || phase == TunnelPhase.PermissionRequired) {
            onEgressRefreshFailed("Wait until the tunnel is fully connected or disconnected before probing egress.")
            return
        }
        onRefreshEgressRequest(phase)
    }

    private fun selectProfile(profileId: String) {
        selectedProfileId = profileId
        persistCatalog()
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = current.editor,
            egress = egressState,
        )
    }

    private fun openEditor(editor: TunnelEditorState) {
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = editor,
            egress = egressState,
        )
    }

    private fun closeEditor() {
        val current = stateFlow.value
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = TunnelEditorState(),
            egress = egressState,
        )
    }

    private fun updateEditor(transform: TunnelEditorState.() -> TunnelEditorState) {
        val current = stateFlow.value
        val nextEditor = current.editor.transform()
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = current.detail,
            requiresPermission = current.requiresPermission,
            editor = nextEditor,
            egress = egressState,
        )
    }

    private fun saveEditor() {
        val editor = stateFlow.value.editor
        val validationError = validate(editor)
        if (validationError != null) {
            updateEditor { copy(validationError = validationError) }
            return
        }

        val sourceUrl = editor.sourceUrl.trim()
        val useSourceManagedEndpoint = sourceUrl.isNotBlank()
        val normalizedPolicy = works.relux.vless_tun_app.core.model.TunnelRoutingPolicy(
            routeMasks = parseSuffixMaskText(editor.routeMasksText),
            bypassMasks = parseSuffixMaskText(editor.bypassMasksText),
        ).normalized()
        val savedProfile = TunnelProfile(
            id = editor.profileId ?: buildProfileId(editor.name),
            name = editor.name.trim(),
            host = if (useSourceManagedEndpoint) "" else editor.host.trim(),
            port = if (useSourceManagedEndpoint) 443 else editor.port.toInt(),
            transport = if (useSourceManagedEndpoint) "" else editor.transport.trim().ifBlank { "grpc" },
            sourceMode = editor.sourceMode,
            sourceUrl = sourceUrl,
            serverName = if (useSourceManagedEndpoint) "" else editor.serverName.trim(),
            uuid = if (useSourceManagedEndpoint) "" else editor.uuid.trim(),
            routeMasks = normalizedPolicy.routeMasks,
            bypassMasks = normalizedPolicy.bypassMasks,
        )

        profiles = if (editor.mode == TunnelEditorMode.Create) {
            profiles + savedProfile
        } else {
            profiles.map { profile ->
                if (profile.id == savedProfile.id) savedProfile else profile
            }
        }
        selectedProfileId = savedProfile.id
        persistCatalog()

        val current = stateFlow.value
        val detail = if (current.phase == TunnelPhase.Connected) {
            "Tunnel profile saved. Disconnect and reconnect to apply runtime changes."
        } else {
            "Tunnel profile saved. Ready to connect with the TUN-only runtime."
        }
        stateFlow.value = buildState(
            profiles = profiles,
            selectedId = selectedProfileId,
            phase = current.phase,
            detail = detail,
            requiresPermission = false,
            editor = TunnelEditorState(),
            egress = egressState,
        )
    }

    private fun buildState(
        profiles: List<TunnelProfile>,
        selectedId: String?,
        phase: TunnelPhase,
        detail: String,
        requiresPermission: Boolean,
        editor: TunnelEditorState,
        egress: TunnelEgressState,
    ): TunnelHomeState {
        val selected = profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()
        val preview = selected?.let(renderConfig) ?: "{\n  \"inbounds\": []\n}"
        return TunnelHomeState(
            profiles = profiles.map { profile ->
                TunnelListItemState(
                    id = profile.id,
                    name = profile.name,
                    endpoint = profile.endpoint(),
                    sourceSummary = profile.sourceSummary(),
                    transport = profile.transportLabel(),
                    isSelected = profile.id == selected?.id,
                )
            },
            selectedProfileId = selected?.id,
            profileName = selected?.name ?: "No tunnels configured",
            profileEndpoint = selected?.endpoint() ?: "Add a tunnel to continue",
            profileSourceSummary = selected?.sourceSummary() ?: "No source selected yet",
            phase = phase,
            detail = detail,
            configPreview = preview,
            requiresPermission = requiresPermission,
            editor = editor,
            egress = egress,
        )
    }

    private fun selectedProfile(): TunnelProfile? {
        return profiles.firstOrNull { it.id == selectedProfileId } ?: profiles.firstOrNull()
    }

    private fun findProfile(profileId: String): TunnelProfile? {
        return profiles.firstOrNull { it.id == profileId }
    }

    private fun newEditor(): TunnelEditorState {
        val seed = selectedProfile()
        return TunnelEditorState(
            isVisible = true,
            mode = TunnelEditorMode.Create,
            name = "My Tunnel",
            host = seed?.host ?: "",
            port = seed?.port?.toString() ?: "443",
            transport = seed?.transport ?: "grpc",
            sourceMode = seed?.sourceMode ?: TunnelSourceMode.ProxyResolver,
            sourceUrl = seed?.sourceUrl ?: "https://subscription.example/path",
            serverName = seed?.serverName ?: "",
            uuid = seed?.uuid ?: "",
            routeMasksText = seed?.routingPolicy()?.routeMasksText().orEmpty(),
            bypassMasksText = seed?.routingPolicy()?.bypassMasksText().orEmpty(),
        )
    }

    private fun editorFor(profile: TunnelProfile): TunnelEditorState {
        return TunnelEditorState(
            isVisible = true,
            mode = TunnelEditorMode.Edit,
            profileId = profile.id,
            name = profile.name,
            host = profile.host,
            port = profile.port.toString(),
            transport = profile.transport,
            sourceMode = profile.sourceMode,
            sourceUrl = profile.sourceUrl,
            serverName = profile.serverName,
            uuid = profile.uuid,
            routeMasksText = profile.routingPolicy().routeMasksText(),
            bypassMasksText = profile.routingPolicy().bypassMasksText(),
        )
    }

    private fun validate(editor: TunnelEditorState): String? {
        if (editor.name.isBlank()) return "Tunnel name is required."
        val port = editor.port.toIntOrNull() ?: return "Port must be numeric."
        if (port !in 1..65535) return "Port must be between 1 and 65535."
        val hasSource = editor.sourceUrl.isNotBlank()
        if (!hasSource && editor.host.isBlank()) return "Host is required when no source URL is provided."
        if (!hasSource && editor.serverName.isBlank()) return "Server name is required when no source URL is provided."
        if (!hasSource && editor.uuid.isBlank()) return "UUID is required when no source URL is provided."
        if (editor.sourceMode == TunnelSourceMode.ProxyResolver && !hasSource && editor.host.isBlank()) {
            return "Proxy Resolver mode requires a source URL or an explicit endpoint."
        }
        return null
    }

    private fun buildProfileId(name: String): String {
        val slug = name
            .lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .ifBlank { "tunnel" }
        return "$slug-${profiles.size + 1}"
    }

    private fun persistCatalog() {
        onCatalogChanged(profiles, selectedProfileId)
    }
}
