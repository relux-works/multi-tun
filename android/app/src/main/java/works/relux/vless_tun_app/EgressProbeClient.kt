package works.relux.vless_tun_app

import android.util.Log
import java.net.InetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.EgressObservation

data class EgressProbeResult(
    val bootstrapAddress: String,
    val observation: EgressObservation,
)

class EgressProbeClient(
    private val endpointHost: String = "ip-api.com",
) {
    suspend fun probe(
        phase: TunnelPhase,
        bootstrapAddressHint: String?,
    ): EgressProbeResult = withContext(Dispatchers.IO) {
        val pinnedAddress = if (phase == TunnelPhase.Connected) {
            bootstrapAddressHint
                ?.takeIf(String::isNotBlank)
                ?.let(InetAddress::getByName)
                ?: resolveBootstrapAddress()
        } else {
            resolveBootstrapAddress()
        }
        val resolvedAddress = pinnedAddress.hostAddress
        Log.d(TAG, "Starting egress probe against $endpointHost via $resolvedAddress during phase=$phase")
        val client = OkHttpClient.Builder()
            .dns(
                object : Dns {
                    override fun lookup(hostname: String): List<InetAddress> {
                        return if (hostname == endpointHost) {
                            listOf(pinnedAddress)
                        } else {
                            Dns.SYSTEM.lookup(hostname)
                        }
                    }
                },
            )
            .followRedirects(true)
            .followSslRedirects(true)
            .retryOnConnectionFailure(false)
            .build()
        val request = Request.Builder()
            .url("http://$endpointHost/json?fields=status,message,country,countryCode,query&ts=${System.currentTimeMillis()}")
            .header("Accept", "application/json,text/plain,*/*")
            .header("Cache-Control", "no-cache")
            .build()
        client.newCall(request).execute().use { response ->
            val code = response.code
            if (code !in 200..299) {
                throw IllegalArgumentException("Whoami request failed with HTTP $code.")
            }
            val body = response.body?.string().orEmpty()
            val json = JSONObject(body)
            val status = json.optString("status")
            if (status.isNotBlank() && !status.equals("success", ignoreCase = true)) {
                val message = json.optString("message").ifBlank { "status=$status" }
                throw IllegalArgumentException("Whoami response returned $message.")
            }
            val observation = EgressObservation(
                ip = json.optString("query").ifBlank { json.optString("ip") },
                country = json.optString("country"),
                countryCode = json.optString("countryCode").ifBlank { json.optString("cc") },
            )
            EgressProbeResult(
                bootstrapAddress = resolvedAddress,
                observation = observation,
            ).also {
                Log.d(TAG, "Egress probe resolved ip=${observation.ip} country=${observation.countryCode}")
            }
        }
    }

    private fun resolveBootstrapAddress(): InetAddress {
        return Dns.SYSTEM.lookup(endpointHost).first()
    }

    private companion object {
        const val TAG = "EgressProbeClient"
    }
}
