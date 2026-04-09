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
import kotlinx.coroutines.launch
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.persistence.TunnelCatalog
import works.relux.vless_tun_app.core.persistence.TunnelCatalogStore
import works.relux.vless_tun_app.core.render.TunnelConfigRenderer
import works.relux.vless_tun_app.core.subscription.SourceProfileResolver
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeScreen
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeStore
import works.relux.vless_tun_app.platform.vpnservice.TunnelServiceConnector
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
    val scope = rememberCoroutineScope()
    val renderer = remember { TunnelConfigRenderer() }
    val resolver = remember { SourceProfileResolver() }
    val egressProbe = remember { EgressProbeClient() }
    val connector = remember(context) { TunnelServiceConnector(context) }
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

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            pendingPermissionProfile?.let { connector.connect(it, renderer.render(it)) }
        } else {
            storeRef?.onPermissionDenied()
        }
        pendingPermissionProfile = null
    }

    val store = remember(connector, renderer, resolver, initialCatalog, catalogStore) {
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
                    val permissionIntent = connector.prepareVpnPermissionIntent()
                    if (permissionIntent != null) {
                        pendingPermissionProfile = resolvedProfile
                        permissionLauncher.launch(permissionIntent)
                        storeRef?.onPermissionRequired()
                    } else {
                        connector.connect(resolvedProfile, renderer.render(resolvedProfile))
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

    LaunchedEffect(snapshot) {
        store.syncRuntime(snapshot)
    }

    DisposableEffect(connector) {
        onDispose {
            connector.release()
        }
    }

    TunnelHomeScreen(
        state = state,
        onAction = store::dispatch,
    )
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
    if (resolvedInline != null) {
        return renderer.render(resolvedInline).json
    }
    return if (profile.host.isBlank() || profile.serverName.isBlank() || profile.uuid.isBlank()) {
        """
        {
          "note": "Config preview is deferred until the source URL is resolved at connect time.",
          "source_url_configured": ${profile.sourceUrl.isNotBlank()}
        }
        """.trimIndent()
    } else {
        renderer.render(profile).json
    }
}
