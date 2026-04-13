package works.relux.vless_tun_app

import android.app.Activity
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.routingPolicy
import works.relux.vless_tun_app.core.persistence.CrashLogEntry
import works.relux.vless_tun_app.core.persistence.TunnelCatalog
import works.relux.vless_tun_app.core.persistence.TunnelCatalogStore
import works.relux.vless_tun_app.core.render.TunnelConfigRenderer
import works.relux.vless_tun_app.core.subscription.SourceProfileResolver
import works.relux.vless_tun_app.diagnostics.AppDebugInfo
import works.relux.vless_tun_app.diagnostics.DebugMenuPage
import works.relux.vless_tun_app.diagnostics.DebugMenuDismissGate
import works.relux.vless_tun_app.diagnostics.DebugMenuSheet
import works.relux.vless_tun_app.diagnostics.DebugMenuTapGate
import works.relux.vless_tun_app.diagnostics.buildAppDebugInfo
import works.relux.vless_tun_app.diagnostics.shareCrashLogEntry
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeScreen
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeStore
import works.relux.vless_tun_app.platform.vpnservice.TunnelServiceConnector
import works.relux.vless_tun_app.platform.xray.XrayTunnelConfigRenderer
import works.relux.vless_tun_app.ui.theme.VlessTunTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            VlessTunTheme {
                VlessTunRoot()
            }
        }
    }
}

@Composable
private fun VlessTunRoot() {
    val context = LocalContext.current
    val activity = context as? Activity
    val application = context.applicationContext as VlessTunApplication
    val scope = rememberCoroutineScope()
    val renderer = remember { TunnelConfigRenderer() }
    val xrayRenderer = remember { XrayTunnelConfigRenderer() }
    val resolver = remember { SourceProfileResolver() }
    val egressProbe = remember { EgressProbeClient() }
    val connector = remember(context) { TunnelServiceConnector(context) }
    val crashLogStore = remember(application) { application.crashLogStore }
    val debugMenuDismissGate = remember { DebugMenuDismissGate() }
    val debugMenuTapGate = remember { DebugMenuTapGate() }
    val uiTestConfig = remember(activity?.intent) { UiTestLaunchConfig.fromIntent(activity?.intent) }
    val catalogStore = remember(context) {
        TunnelCatalogStore(
            storageFile = File(context.filesDir, "config/tunnel-catalog.json"),
        )
    }
    val initialCatalog = remember(catalogStore) {
        catalogStore.load(defaultCatalog = defaultCatalog())
    }
    var storeRef by remember { mutableStateOf<TunnelHomeStore?>(null) }
    var pendingPermissionProfile by remember { mutableStateOf<works.relux.vless_tun_app.core.model.TunnelProfile?>(null) }
    var egressBootstrapAddress by rememberSaveable { mutableStateOf<String?>(null) }
    var didApplyUiTestBootAction by rememberSaveable { mutableStateOf(false) }
    var isDebugMenuVisible by rememberSaveable { mutableStateOf(false) }
    var selectedDebugMenuPage by rememberSaveable { mutableStateOf(DebugMenuPage.AppInfo) }
    var appDebugInfo by remember { mutableStateOf<AppDebugInfo?>(null) }
    var crashEntries by remember { mutableStateOf<List<CrashLogEntry>>(emptyList()) }
    var isLoadingCrashEntries by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            pendingPermissionProfile?.let { profile ->
                runCatching {
                    if (profile.transport.equals("xhttp", ignoreCase = true)) {
                        xrayRenderer.render(profile)
                    } else {
                        renderer.render(profile)
                    }
                }
                    .onSuccess { renderedConfig ->
                        connector.connect(profile, renderedConfig)
                    }
                    .onFailure { error ->
                        storeRef?.onConnectFailed(error.message ?: "Failed to build tunnel config.")
                    }
            }
        } else {
            storeRef?.onPermissionDenied()
        }
        pendingPermissionProfile = null
    }

    val store = remember(connector, renderer, xrayRenderer, resolver, initialCatalog, catalogStore) {
        TunnelHomeStore(
            initialProfiles = initialCatalog.profiles,
            initialSelectedProfileId = initialCatalog.selectedProfileId,
            renderConfig = { profile -> previewConfig(profile, renderer, resolver) },
            onConnectRequest = { profile ->
                scope.launch {
                    val resolvedProfile = runCatching { resolver.resolve(profile) }
                        .getOrElse { error ->
                            storeRef?.onConnectFailed(error.message ?: "Failed to resolve source URL.")
                            return@launch
                        }
                    val renderedConfig = runCatching {
                        if (resolvedProfile.transport.equals("xhttp", ignoreCase = true)) {
                            xrayRenderer.render(resolvedProfile)
                        } else {
                            renderer.render(resolvedProfile)
                        }
                    }
                        .getOrElse { error ->
                            storeRef?.onConnectFailed(error.message ?: "Failed to build tunnel config.")
                            return@launch
                        }
                    val permissionIntent = connector.prepareVpnPermissionIntent()
                    if (permissionIntent != null) {
                        pendingPermissionProfile = resolvedProfile
                        permissionLauncher.launch(permissionIntent)
                        storeRef?.onPermissionRequired()
                    } else {
                        connector.connect(resolvedProfile, renderedConfig)
                    }
                }
            },
            onDisconnectRequest = connector::disconnect,
            onRefreshEgressRequest = { phase ->
                scope.launch {
                    storeRef?.onEgressRefreshStarted()
                    runCatching { egressProbe.probe(phase, egressBootstrapAddress) }
                        .onSuccess { result ->
                            egressBootstrapAddress = result.bootstrapAddress
                            Log.d(TAG, "Egress probe succeeded during phase=$phase with ip=${result.observation.ip}")
                            storeRef?.onEgressObserved(phase, result.observation)
                        }
                        .onFailure { error ->
                            val message = error.toUiMessage("Failed to probe app egress.")
                            Log.e(TAG, "Egress probe failed during phase=$phase: $message", error)
                            storeRef?.onEgressRefreshFailed(message)
                        }
                }
            },
            onCatalogChanged = { profiles, selectedProfileId ->
                catalogStore.save(
                    TunnelCatalog(
                        profiles = profiles,
                        selectedProfileId = selectedProfileId,
                    ),
                )
            },
        )
    }

    val snapshot by connector.snapshots.collectAsState()
    val state by store.state.collectAsState()

    LaunchedEffect(store) {
        storeRef = store
    }

    LaunchedEffect(connector) {
        connector.syncWithRunningService()
    }

    LaunchedEffect(store, uiTestConfig, didApplyUiTestBootAction) {
        if (didApplyUiTestBootAction) return@LaunchedEffect
        when (uiTestConfig.action) {
            UiTestLaunchContract.ACTION_OPEN_CREATE_EDITOR -> {
                store.dispatch(works.relux.vless_tun_app.feature.tunnel.TunnelHomeAction.AddTunnelClicked)
            }
            UiTestLaunchContract.ACTION_OPEN_EDIT_SELECTED_EDITOR -> {
                store.state.value.selectedProfileId?.let { selectedProfileId ->
                    store.dispatch(
                        works.relux.vless_tun_app.feature.tunnel.TunnelHomeAction.EditTunnelClicked(selectedProfileId),
                    )
                }
            }
        }
        didApplyUiTestBootAction = true
    }

    LaunchedEffect(snapshot) {
        store.syncRuntime(snapshot)
    }

    DisposableEffect(connector) {
        onDispose {
            connector.release()
        }
    }

    LaunchedEffect(isDebugMenuVisible) {
        if (!isDebugMenuVisible) {
            return@LaunchedEffect
        }
        appDebugInfo = buildAppDebugInfo(
            context = context,
            crashDatabasePath = crashLogStore.databasePath(),
            tunnelCatalogPath = catalogStore.storagePath(),
        )
        isLoadingCrashEntries = true
        crashEntries = withContext(Dispatchers.IO) { crashLogStore.listRecent() }
        isLoadingCrashEntries = false
    }

    TunnelHomeScreen(
        state = state,
        onAction = store::dispatch,
        editorPinnedTop = uiTestConfig.editorPinnedTop,
        onHeaderTap = {
            if (isDebugMenuVisible) {
                return@TunnelHomeScreen
            }
            if (debugMenuTapGate.registerTap()) {
                debugMenuDismissGate.markOpened()
                selectedDebugMenuPage = DebugMenuPage.AppInfo
                isDebugMenuVisible = true
            }
        },
    )

    if (isDebugMenuVisible) {
        DebugMenuSheet(
            appInfo = appDebugInfo ?: buildAppDebugInfo(
                context = context,
                crashDatabasePath = crashLogStore.databasePath(),
                tunnelCatalogPath = catalogStore.storagePath(),
            ),
            crashEntries = crashEntries,
            isLoadingExceptions = isLoadingCrashEntries,
            selectedPage = selectedDebugMenuPage,
            onPageSelected = { selectedDebugMenuPage = it },
            onShareCrashEntry = { entry -> shareCrashLogEntry(context, entry) },
            canDismiss = debugMenuDismissGate::canDismiss,
            onDismiss = {
                if (!debugMenuDismissGate.canDismiss()) {
                    return@DebugMenuSheet
                }
                debugMenuDismissGate.reset()
                debugMenuTapGate.reset()
                isDebugMenuVisible = false
            },
        )
    }
}

private fun Throwable.toUiMessage(fallback: String): String {
    val simpleName = this::class.java.simpleName.takeIf { it.isNotBlank() }
    val message = message?.takeIf { it.isNotBlank() }
    return when {
        simpleName != null && message != null -> "$simpleName: $message"
        message != null -> message
        simpleName != null -> simpleName
        else -> fallback
    }
}

private const val TAG = "MainActivity"

private fun defaultCatalog(): TunnelCatalog {
    return TunnelCatalog(
        profiles = DefaultTunnelCatalog.defaultProfiles,
        selectedProfileId = DefaultTunnelCatalog.defaultProfile.id,
    )
}

private fun previewConfig(
    profile: works.relux.vless_tun_app.core.model.TunnelProfile,
    renderer: TunnelConfigRenderer,
    resolver: SourceProfileResolver,
): String {
    val resolvedInline = resolver.resolveInline(profile)
    if (resolvedInline?.transport.equals("xhttp", ignoreCase = true)) {
        return """
        {
          "note": "Config preview is deferred until connect time because this tunnel uses the Xray-backed xhttp transport path.",
          "source_url": "${resolvedInline?.sourceUrl?.replace("\"", "\\\"") ?: ""}",
          "resolved_on_connect": true,
          "runtime_backend": "xray"
        }
        """.trimIndent()
    }
    if (resolvedInline != null) {
        return renderer.render(resolvedInline).json
    }
    return if (profile.sourceUrl.isNotBlank()) {
        val sourceSummary = profile.sourceUrl.lineSequence().firstOrNull()?.trim().orEmpty()
        val routingPolicy = profile.routingPolicy()
        """
        {
          "note": "Config preview is deferred until connect time because this tunnel resolves from a source URL.",
          "source_url": "${sourceSummary.replace("\"", "\\\"")}",
          "routing": {
            "route_masks": [${routingPolicy.routeMasks.joinToString(", ") { "\"${it.replace("\"", "\\\"")}\"" }}],
            "bypass_masks": [${routingPolicy.bypassMasks.joinToString(", ") { "\"${it.replace("\"", "\\\"")}\"" }}]
          },
          "resolved_on_connect": true
        }
        """.trimIndent()
    } else if (profile.host.isBlank() || profile.serverName.isBlank() || profile.uuid.isBlank()) {
        """
        {
          "note": "Manual endpoint is incomplete. Fill host, server name, and UUID or paste a source URL.",
          "manual_endpoint_complete": false
        }
        """.trimIndent()
    } else {
        renderer.render(profile).json
    }
}
