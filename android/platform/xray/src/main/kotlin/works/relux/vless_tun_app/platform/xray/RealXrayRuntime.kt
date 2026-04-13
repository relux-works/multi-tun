package works.relux.vless_tun_app.platform.xray

import android.util.Log
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libXray.DialerController
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot

class RealXrayRuntime(
    private val host: XrayRuntimeHost,
) {
    private val dialerController = object : DialerController {
        override fun protectFd(fd: Long): Boolean = host.protectFd(fd.toInt())
    }

    suspend fun start(
        profile: TunnelProfile,
        config: RenderedTunnelConfig,
    ): TunnelRuntimeSnapshot = withContext(Dispatchers.IO) {
        Log.i(TAG, "start profile=${profile.name} endpoint=${profile.host}:${profile.port} transport=${profile.transport}")
        runCatching {
            if (LibXrayBridge.isRunning()) {
                runCatching { LibXrayBridge.stopXray() }
            }
            LibXrayBridge.resetDns()

            val tunHandle = host.openTun(config.runtimeManifest)
            val datDir = ensureRuntimeDataDir()
            val mphCachePath = ensureRuntimeCachePath()
            val dnsServer = config.runtimeManifest.dnsServers.firstOrNull().orEmpty().ifBlank { DEFAULT_DNS_SERVER }

            LibXrayBridge.registerControllers(dialerController)
            LibXrayBridge.initDns(dialerController, dnsServer)
            LibXrayBridge.setTunFd(tunHandle.fd)
            LibXrayBridge.runXrayFromJson(
                datDir = datDir.absolutePath,
                mphCachePath = mphCachePath.absolutePath,
                configJson = config.json,
            )

            TunnelRuntimeSnapshot(
                phase = TunnelPhase.Connected,
                activeProfileName = profile.name,
                detail = "${tunHandle.summary} Xray ${LibXrayBridge.xrayVersion()} is active.",
                renderedConfigPreview = config.json.take(220),
            )
        }.getOrElse { error ->
            Log.e(TAG, "start failed", error)
            runCatching { LibXrayBridge.stopXray() }
            LibXrayBridge.resetDns()
            host.closeTunInterface()
            TunnelRuntimeSnapshot(
                phase = TunnelPhase.Error,
                activeProfileName = profile.name,
                detail = error.message ?: "Failed to start the Xray-backed runtime.",
                renderedConfigPreview = config.json.take(220),
            )
        }
    }

    suspend fun stop(): TunnelRuntimeSnapshot = withContext(Dispatchers.IO) {
        runCatching { LibXrayBridge.stopXray() }
        LibXrayBridge.resetDns()
        host.closeTunInterface()
        TunnelRuntimeSnapshot(
            phase = TunnelPhase.Disconnected,
            detail = "Xray tunnel stopped.",
        )
    }

    private fun ensureRuntimeDataDir(): File {
        return File(host.context.filesDir, "xray/data").apply {
            mkdirs()
        }
    }

    private fun ensureRuntimeCachePath(): File {
        return File(host.context.filesDir, "xray/cache/matcher.cache").apply {
            parentFile?.mkdirs()
        }
    }

    private companion object {
        const val TAG = "RealXrayRuntime"
        const val DEFAULT_DNS_SERVER = "1.1.1.1"
    }
}
