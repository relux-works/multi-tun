package works.relux.vless_tun_observer

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request

class ObserverActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ObserverActivityExtras.install(
            bootstrapIp = intent.getStringExtra(ObserverActivityExtras.BOOTSTRAP_IP),
            targetHost = intent.getStringExtra(ObserverActivityExtras.TARGET_HOST),
        )
        enableEdgeToEdge()
        setContent {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .semantics { testTagsAsResourceId = true },
                color = MaterialTheme.colorScheme.background,
            ) {
                ObserverScreen()
            }
        }
    }
}

@Composable
private fun ObserverScreen() {
    val scope = rememberCoroutineScope()
    val appContext = LocalContext.current.applicationContext
    val bootstrapIp = remember {
        ObserverActivityExtras.bootstrapIp()
    }
    val targetHost = remember {
        ObserverActivityExtras.targetHost()
    }
    val client = remember(targetHost, bootstrapIp) { ObserverProbeClient(targetHost, bootstrapIp) }
    val networkInspector = remember(appContext) { ObserverNetworkInspector(appContext) }
    var state by remember { mutableStateOf(ObserverState()) }

    fun refresh() {
        scope.launch {
            state = state.copy(
                isLoading = true,
                observation = null,
                visibility = null,
                error = null,
            )
            Log.i(TAG, "OBSERVER_PROBE_START")
            val visibility = runCatching {
                withContext(Dispatchers.IO) {
                    networkInspector.capture()
                }
            }.getOrElse { error ->
                ObserverNetworkVisibility.unavailable(
                    note = error.message ?: "network_visibility_capture_failed",
                )
            }
            runCatching {
                withContext(Dispatchers.IO) {
                    client.probe()
                }
            }
                .onSuccess { observation ->
                    Log.i(
                        TAG,
                        "OBSERVER_PROBE_SUCCESS host=${observation.targetHost} ip=${observation.ip} " +
                            "vpnVisible=${visibility.vpnTransportVisibleText()}",
                    )
                    state = state.copy(
                        isLoading = false,
                        observation = observation,
                        visibility = visibility,
                        error = null,
                    )
                }
                .onFailure { error ->
                    val message = error.toUiMessage("Observer probe failed.")
                    Log.e(TAG, "OBSERVER_PROBE_FAIL message=$message", error)
                    state = state.copy(
                        isLoading = false,
                        visibility = visibility,
                        error = message,
                    )
                }
        }
    }

    LaunchedEffect(Unit) {
        refresh()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 24.dp)
            .testTag(ObserverTags.SCREEN),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Tunnel Observer",
            modifier = Modifier.testTag(ObserverTags.TITLE),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            text = "This helper app runs under a different UID and reports both live egress and system network visibility for the selected endpoint.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Probe target",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = targetHost,
                    modifier = Modifier.testTag(ObserverTags.TARGET_HOST),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
        Button(
            modifier = Modifier
                .fillMaxWidth()
                .testTag(ObserverTags.REFRESH_BUTTON),
            enabled = !state.isLoading,
            onClick = ::refresh,
        ) {
            Text(if (state.isLoading) "Checking..." else "Refresh Observer Egress")
        }
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Observed egress",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = state.observation?.summary() ?: "Not captured yet",
                    modifier = Modifier.testTag(ObserverTags.RESULT),
                    style = MaterialTheme.typography.bodyLarge,
                )
                state.error?.takeIf(String::isNotBlank)?.let { error ->
                    Text(
                        text = error,
                        modifier = Modifier.testTag(ObserverTags.ERROR),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Network visibility",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = state.visibility?.summary() ?: "Not captured yet",
                    modifier = Modifier.testTag(ObserverTags.NETWORK_RESULT),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = state.visibility?.vpnTransportVisibleText() ?: "unknown",
                    modifier = Modifier.testTag(ObserverTags.VPN_VISIBLE),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private data class ObserverState(
    val isLoading: Boolean = false,
    val observation: ObserverObservation? = null,
    val visibility: ObserverNetworkVisibility? = null,
    val error: String? = null,
)

private data class ObserverObservation(
    val targetHost: String,
    val ip: String,
) {
    fun summary(): String = ip
}

private data class ObserverNetworkVisibility(
    val vpnTransportVisible: Boolean?,
    val activeInterfaceName: String,
    val activeTransports: List<String>,
    val visibleNetworks: List<String>,
    val note: String = "",
) {
    fun summary(): String = buildString {
        append("vpn_transport_visible=")
        append(vpnTransportVisibleText())
        append(" active_iface=")
        append(activeInterfaceName.ifBlank { "none" })
        append(" active_transports=")
        append(activeTransports.joinToString("+").ifBlank { "none" })
        if (visibleNetworks.isNotEmpty()) {
            append(" visible_networks=")
            append(visibleNetworks.joinToString(","))
        }
        if (note.isNotBlank()) {
            append(" note=")
            append(note)
        }
    }

    fun vpnTransportVisibleText(): String = vpnTransportVisible?.toString() ?: "unknown"

    companion object {
        fun unavailable(note: String): ObserverNetworkVisibility {
            return ObserverNetworkVisibility(
                vpnTransportVisible = null,
                activeInterfaceName = "",
                activeTransports = emptyList(),
                visibleNetworks = emptyList(),
                note = note,
            )
        }
    }
}

private data class ObserverNetworkSnapshot(
    val handle: Long,
    val interfaceName: String,
    val transports: List<String>,
    val hasInternet: Boolean,
    val hasVpnTransport: Boolean,
) {
    fun summary(): String = buildString {
        append(handle)
        append(':')
        append(interfaceName.ifBlank { "unknown" })
        append('[')
        append(transports.joinToString("+").ifBlank { "none" })
        append(']')
    }
}

private class ObserverProbeClient {
    constructor(
        targetHost: String,
        bootstrapIp: String?,
    ) {
        this.targetHost = targetHost
        client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .dns(
                if (bootstrapIp.isNullOrBlank()) {
                    Dns.SYSTEM
                } else {
                    ObserverPinnedDns(
                        targetHost = targetHost,
                        bootstrapIp = bootstrapIp,
                    )
                },
            )
            .build()
    }

    private val client: OkHttpClient
    private val targetHost: String

    fun probe(): ObserverObservation {
        repeat(3) { attempt ->
            runCatching {
                val request = Request.Builder()
                    .url("https://$targetHost?format=text&ts=${System.currentTimeMillis()}")
                    .header("Accept", "text/plain,application/json,*/*")
                    .header("Cache-Control", "no-cache")
                    .build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IOException("Observer whoami failed for $targetHost with HTTP ${response.code}.")
                    }
                    val ip = response.body?.string().orEmpty()
                        .lineSequence()
                        .map(String::trim)
                        .firstOrNull(String::isNotBlank)
                        .orEmpty()
                    if (ip.isBlank()) {
                        throw IOException("Observer whoami response for $targetHost does not contain an IP.")
                    }
                    ObserverObservation(
                        targetHost = targetHost,
                        ip = ip,
                    )
                }
            }.onSuccess { return it }

            if (attempt < 2) {
                Thread.sleep(1_000)
            }
        }

        throw IOException("Observer whoami failed for $targetHost after retries.")
    }
}

private class ObserverNetworkInspector(
    appContext: Context,
) {
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)

    fun capture(): ObserverNetworkVisibility {
        val connectivity = connectivity
            ?: return ObserverNetworkVisibility.unavailable("connectivity_manager=unavailable")
        val internetNetworks = connectivity.allNetworks
            .mapNotNull { network -> snapshot(connectivity, network) }
            .filter(ObserverNetworkSnapshot::hasInternet)
        val activeNetwork = connectivity.activeNetwork?.let { network ->
            snapshot(connectivity, network)
        }
        return ObserverNetworkVisibility(
            vpnTransportVisible = internetNetworks.any(ObserverNetworkSnapshot::hasVpnTransport),
            activeInterfaceName = activeNetwork?.interfaceName.orEmpty(),
            activeTransports = activeNetwork?.transports.orEmpty(),
            visibleNetworks = internetNetworks.map(ObserverNetworkSnapshot::summary),
            note = if (activeNetwork == null) "active_network=none" else "",
        )
    }

    private fun snapshot(
        connectivity: ConnectivityManager,
        network: Network,
    ): ObserverNetworkSnapshot? {
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return null
        val linkProperties = connectivity.getLinkProperties(network)
        return ObserverNetworkSnapshot(
            handle = network.networkHandle,
            interfaceName = linkProperties?.interfaceName.orEmpty(),
            transports = capabilities.transportLabels(),
            hasInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            hasVpnTransport = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
        )
    }
}

private fun NetworkCapabilities.transportLabels(): List<String> = buildList {
    if (hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
    if (hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("WIFI")
    if (hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("CELLULAR")
    if (hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ETHERNET")
    if (hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("BLUETOOTH")
}

private object ObserverActivityExtras {
    const val BOOTSTRAP_IP = "observer_bootstrap_ip"
    const val TARGET_HOST = "observer_target_host"

    private var currentBootstrapIp: String? = null
    private var currentTargetHost: String = DEFAULT_PROBE_HOST

    fun install(
        bootstrapIp: String?,
        targetHost: String?,
    ) {
        currentBootstrapIp = bootstrapIp.sanitizedExtra()
        currentTargetHost = targetHost.sanitizedExtra()
            ?: DEFAULT_PROBE_HOST
    }

    fun bootstrapIp(): String? = currentBootstrapIp
    fun targetHost(): String = currentTargetHost

    private fun String?.sanitizedExtra(): String? {
        return this
            ?.trim()
            ?.trim('\'', '"')
            ?.takeIf(String::isNotBlank)
    }
}

private class ObserverPinnedDns(
    private val targetHost: String,
    private val bootstrapIp: String,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (!hostname.equals(targetHost, ignoreCase = true)) {
            return Dns.SYSTEM.lookup(hostname)
        }
        return listOf(InetAddress.getByName(bootstrapIp))
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

private const val TAG = "ObserverActivity"
private const val DEFAULT_PROBE_HOST = "api.ipify.org"
