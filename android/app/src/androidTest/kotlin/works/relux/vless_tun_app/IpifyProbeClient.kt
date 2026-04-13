package works.relux.vless_tun_app

import okhttp3.OkHttpClient
import okhttp3.Request

internal object IpifyProbeClient {
    fun probe(host: String): String {
        val client = OkHttpClient.Builder()
            .retryOnConnectionFailure(false)
            .build()

        repeat(3) { attempt ->
            runCatching {
                val request = Request.Builder()
                    .url("https://$host?format=text&ts=${System.currentTimeMillis()}")
                    .header("Cache-Control", "no-cache")
                    .build()
                client.newCall(request).execute().use { response ->
                    check(response.isSuccessful) { "HTTP ${response.code}" }
                    response.body?.string().orEmpty().trim()
                }.also { body ->
                    check(body.isNotBlank()) { "empty response body" }
                }
            }.onSuccess { return it }

            if (attempt < 2) {
                Thread.sleep(1_000)
            }
        }

        error("Failed to probe $host after retries.")
    }
}
