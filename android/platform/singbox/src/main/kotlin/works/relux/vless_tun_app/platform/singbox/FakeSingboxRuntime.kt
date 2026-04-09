package works.relux.vless_tun_app.platform.singbox

import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot

class FakeSingboxRuntime {
    suspend fun start(
        profile: TunnelProfile,
        config: RenderedTunnelConfig,
        tunFd: Int,
        protectSocket: (Socket) -> Boolean = { true },
    ): TunnelRuntimeSnapshot {
        delay(250)
        val routeSummary = config.runtimeManifest.routes.joinToString { route ->
            "${route.address}/${route.prefixLength}"
        }
        val probeResult = withContext(Dispatchers.IO) {
            probeUpstream(
                profile = profile,
                shouldProtect = !config.runtimeManifest.isMockDataPlane,
                protectSocket = protectSocket,
            )
        }
        val probeLabel = if (config.runtimeManifest.isMockDataPlane) {
            "system-network bootstrap probe ok"
        } else {
            "upstream bootstrap probe ok"
        }
        return if (probeResult.success) {
            TunnelRuntimeSnapshot(
                phase = TunnelPhase.Connected,
                activeProfileName = profile.name,
                detail = "TUN interface established on fd=$tunFd with route set $routeSummary. $probeLabel. sing-box data plane is still mocked.",
                renderedConfigPreview = config.json.take(220),
            )
        } else {
            TunnelRuntimeSnapshot(
                phase = TunnelPhase.Error,
                activeProfileName = profile.name,
                detail = "TUN interface established on fd=$tunFd, but bootstrap probe failed: ${probeResult.reason}",
                renderedConfigPreview = config.json.take(220),
            )
        }
    }

    suspend fun stop(): TunnelRuntimeSnapshot {
        delay(250)
        return TunnelRuntimeSnapshot(
            phase = TunnelPhase.Disconnected,
            detail = "Stub tunnel stopped.",
        )
    }

    private fun probeUpstream(
        profile: TunnelProfile,
        shouldProtect: Boolean,
        protectSocket: (Socket) -> Boolean,
    ): ProbeResult {
        if (profile.host.isBlank()) {
            return ProbeResult(success = false, reason = "resolved host is empty")
        }

        return runCatching {
            Socket().use { socket ->
                if (shouldProtect && !protectSocket(socket)) {
                    return ProbeResult(success = false, reason = "VpnService.protect(socket) returned false")
                }
                socket.soTimeout = CONNECT_TIMEOUT_MS
                socket.connect(
                    InetSocketAddress(profile.host, profile.port),
                    CONNECT_TIMEOUT_MS,
                )
            }
            ProbeResult(success = true, reason = "ok")
        }.getOrElse { error ->
            ProbeResult(
                success = false,
                reason = error.message ?: error::class.java.simpleName,
            )
        }
    }

    private data class ProbeResult(
        val success: Boolean,
        val reason: String,
    )

    private companion object {
        const val CONNECT_TIMEOUT_MS = 5000
    }
}
