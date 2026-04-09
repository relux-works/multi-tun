package works.relux.vless_tun_observer

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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import java.io.IOException
import java.net.InetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

class ObserverActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ObserverActivityExtras.install(intent.getStringExtra(ObserverActivityExtras.BOOTSTRAP_IP))
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
    val bootstrapIp = remember {
        ObserverActivityExtras.bootstrapIp()
    }
    val client = remember(bootstrapIp) { ObserverProbeClient(bootstrapIp) }
    var state by remember { mutableStateOf(ObserverState()) }

    fun refresh() {
        scope.launch {
            state = state.copy(
                isLoading = true,
                error = null,
            )
            Log.i(TAG, "OBSERVER_PROBE_START")
            runCatching {
                withContext(Dispatchers.IO) {
                    client.probe()
                }
            }
                .onSuccess { observation ->
                    Log.i(TAG, "OBSERVER_PROBE_SUCCESS ip=${observation.ip} country=${observation.countryCode}")
                    state = state.copy(
                        isLoading = false,
                        observation = observation,
                        error = null,
                    )
                }
                .onFailure { error ->
                    val message = error.toUiMessage("Observer probe failed.")
                    Log.e(TAG, "OBSERVER_PROBE_FAIL message=$message", error)
                    state = state.copy(
                        isLoading = false,
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
            text = "This helper app runs under a different UID and shows the live public egress seen outside the VPN host process.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
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
    }
}

private data class ObserverState(
    val isLoading: Boolean = false,
    val observation: ObserverObservation? = null,
    val error: String? = null,
)

private data class ObserverObservation(
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

private class ObserverProbeClient {
    constructor(bootstrapIp: String?) {
        client = OkHttpClient.Builder()
            .retryOnConnectionFailure(false)
            .dns(
                if (bootstrapIp.isNullOrBlank()) {
                    Dns.SYSTEM
                } else {
                    ObserverPinnedDns(bootstrapIp)
                },
            )
            .build()
    }

    private val client: OkHttpClient

    fun probe(): ObserverObservation {
        val request = Request.Builder()
            .url("http://$WHOAMI_HOST/json?fields=status,message,country,countryCode,query&ts=${System.currentTimeMillis()}")
            .header("Accept", "application/json,text/plain,*/*")
            .header("Cache-Control", "no-cache")
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Observer whoami failed with HTTP ${response.code}.")
            }
            val body = response.body?.string().orEmpty()
            val json = JSONObject(body)
            val status = json.optString("status")
            if (status.isNotBlank() && !status.equals("success", ignoreCase = true)) {
                val message = json.optString("message").ifBlank { "status=$status" }
                throw IOException("Observer whoami returned $message.")
            }
            return ObserverObservation(
                ip = json.optString("query").ifBlank { json.optString("ip") },
                country = json.optString("country"),
                countryCode = json.optString("countryCode").ifBlank { json.optString("cc") },
            )
        }
    }
}

private object ObserverActivityExtras {
    const val BOOTSTRAP_IP = "observer_bootstrap_ip"

    private var currentBootstrapIp: String? = null

    fun install(bootstrapIp: String?) {
        currentBootstrapIp = bootstrapIp
            ?.trim()
            ?.trim('\'', '"')
            ?.takeIf(String::isNotBlank)
    }

    fun bootstrapIp(): String? = currentBootstrapIp
}

private class ObserverPinnedDns(
    private val bootstrapIp: String,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (!hostname.equals(WHOAMI_HOST, ignoreCase = true)) {
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
private const val WHOAMI_HOST = "ip-api.com"
