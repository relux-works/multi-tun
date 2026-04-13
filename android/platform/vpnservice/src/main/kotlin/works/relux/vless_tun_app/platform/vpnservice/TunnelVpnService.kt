package works.relux.vless_tun_app.platform.vpnservice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.IpPrefix
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.StringBox
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import java.net.InetAddress
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeBackend
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeManifest
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot
import works.relux.vless_tun_app.core.runtime.TunnelTunHandle
import works.relux.vless_tun_app.platform.singbox.RealSingboxRuntime
import works.relux.vless_tun_app.platform.singbox.SingboxRuntimeHost
import works.relux.vless_tun_app.platform.xray.RealXrayRuntime
import works.relux.vless_tun_app.platform.xray.XrayRuntimeHost

class TunnelVpnService : VpnService(), SingboxRuntimeHost, XrayRuntimeHost {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val singboxRuntime by lazy { RealSingboxRuntime(this) }
    private val xrayRuntime by lazy { RealXrayRuntime(this) }
    private var tunInterface: ParcelFileDescriptor? = null
    private var activeConfig: RenderedTunnelConfig? = null
    private var activeBackend: TunnelRuntimeBackend? = null
    private val snapshotFlow = MutableStateFlow(
        TunnelRuntimeSnapshot(
            detail = "TunnelVpnService is idle.",
        ),
    )
    private val localBinder = LocalBinder()

    override val context = this

    override fun onBind(intent: Intent): IBinder? {
        Log.i(TAG, "onBind action=${intent.action}")
        return if (intent.action == SERVICE_INTERFACE) {
            super.onBind(intent)
        } else {
            localBinder
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureForegroundService()
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        stopForeground(STOP_FOREGROUND_REMOVE)
        closeTunInterface()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "onRevoke")
        stopForeground(STOP_FOREGROUND_REMOVE)
        closeTunInterface()
        snapshotFlow.value = TunnelRuntimeSnapshot(
            phase = TunnelPhase.Disconnected,
            detail = "VPN permission was revoked. Tunnel interface closed.",
        )
        stopSelf()
        super.onRevoke()
    }

    inner class LocalBinder : Binder() {
        fun snapshots(): StateFlow<TunnelRuntimeSnapshot> = snapshotFlow.asStateFlow()

        fun connect(
            profile: TunnelProfile,
            config: RenderedTunnelConfig,
        ) {
            startTunnel(profile, config)
        }

        fun disconnect() {
            stopTunnel()
        }
    }

    override fun openTun(options: TunOptions): TunnelTunHandle {
        Log.i(TAG, "openTun mtu=${options.getMTU()} autoRoute=${options.getAutoRoute()}")
        closeTunInterface()

        val builder = Builder()
            .setSession("vless-tun")
            .setMtu(options.getMTU())
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        builder.allowBypass()
        currentUnderlyingNetworks()?.let(builder::setUnderlyingNetworks)

        val inet4Addresses = collectRoutePrefixes(options.getInet4Address())
        val inet6Addresses = collectRoutePrefixes(options.getInet6Address())
        val inet4Routes = collectRoutePrefixes(options.getInet4RouteAddress())
        val inet6Routes = collectRoutePrefixes(options.getInet6RouteAddress())
        val inet4Excludes = collectRoutePrefixes(options.getInet4RouteExcludeAddress())
        val inet6Excludes = collectRoutePrefixes(options.getInet6RouteExcludeAddress())
        val includePackages = collectStrings(options.getIncludePackage())
        val excludePackages = collectStrings(options.getExcludePackage())
        val dnsServers = activeConfig
            ?.runtimeManifest
            ?.dnsServers
            ?.filter(String::isNotBlank)
            ?.distinct()
            ?.ifEmpty { null }
            ?: options.getDNSServerAddress().value
                .takeIf(String::isNotBlank)
                ?.let(::listOf)
                .orEmpty()

        inet4Addresses.forEach { prefix ->
            builder.addAddress(prefix.address(), prefix.prefix())
        }
        inet6Addresses.forEach { prefix ->
            builder.addAddress(prefix.address(), prefix.prefix())
        }

        if (options.getAutoRoute()) {
            dnsServers.forEach(builder::addDnsServer)

            if (inet4Routes.isNotEmpty()) {
                inet4Routes.forEach { prefix ->
                    builder.addRoute(prefix.address(), prefix.prefix())
                }
            } else if (inet4Addresses.isNotEmpty()) {
                builder.addRoute("0.0.0.0", 0)
            }

            if (inet6Routes.isNotEmpty()) {
                inet6Routes.forEach { prefix ->
                    builder.addRoute(prefix.address(), prefix.prefix())
                }
            } else if (inet6Addresses.isNotEmpty()) {
                builder.addRoute("::", 0)
            }

            inet4Excludes.forEach { prefix ->
                builder.excludeRoute(IpPrefix(InetAddress.getByName(prefix.address()), prefix.prefix()))
            }
            inet6Excludes.forEach { prefix ->
                builder.excludeRoute(IpPrefix(InetAddress.getByName(prefix.address()), prefix.prefix()))
            }
        }

        includePackages.forEach { packageName ->
            runCatching {
                builder.addAllowedApplication(packageName)
            }.onFailure { error ->
                if (error !is PackageManager.NameNotFoundException) {
                    throw error
                }
            }
        }

        excludePackages.forEach { packageName ->
            runCatching {
                builder.addDisallowedApplication(packageName)
            }.onFailure { error ->
                if (error !is PackageManager.NameNotFoundException) {
                    throw error
                }
            }
        }

        val descriptor = builder.establish()
            ?: error("VpnService.Builder.establish() returned null. The VPN permission was likely revoked.")
        tunInterface = descriptor
        Log.i(TAG, "VpnService establish returned fd=${descriptor.fd}")

        val routeSummaryParts = mutableListOf<String>()
        if (inet4Routes.isNotEmpty()) {
            routeSummaryParts += inet4Routes.map { prefix -> "${prefix.address()}/${prefix.prefix()}" }
        } else if (inet4Addresses.isNotEmpty()) {
            routeSummaryParts += "0.0.0.0/0"
        }
        if (inet6Routes.isNotEmpty()) {
            routeSummaryParts += inet6Routes.map { prefix -> "${prefix.address()}/${prefix.prefix()}" }
        } else if (inet6Addresses.isNotEmpty()) {
            routeSummaryParts += "::/0"
        }

        val summary = buildString {
            append("TUN interface established on fd=${descriptor.fd} with route set ")
            append(routeSummaryParts.joinToString().ifBlank { "none" })
            if (dnsServers.isNotEmpty()) {
                append(". DNS=")
                append(dnsServers.joinToString())
            }
            if (excludePackages.isNotEmpty()) {
                append(". Excluded apps=")
                append(excludePackages.joinToString())
            }
        }

        return TunnelTunHandle(
            fd = descriptor.fd,
            summary = summary,
        )
    }

    override fun openTun(manifest: TunnelRuntimeManifest): TunnelTunHandle {
        Log.i(TAG, "openTun manifest mtu=${manifest.mtu} session=${manifest.sessionName}")
        closeTunInterface()

        val builder = Builder()
            .setSession(manifest.sessionName)
            .setMtu(manifest.mtu)
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        if (manifest.allowBypass) {
            builder.allowBypass()
        }
        currentUnderlyingNetworks()?.let(builder::setUnderlyingNetworks)

        manifest.addresses.forEach { address ->
            builder.addAddress(address.address, address.prefixLength)
        }
        manifest.dnsServers
            .filter(String::isNotBlank)
            .distinct()
            .forEach(builder::addDnsServer)
        manifest.routes.forEach { route ->
            builder.addRoute(route.address, route.prefixLength)
        }

        val descriptor = builder.establish()
            ?: error("VpnService.Builder.establish() returned null. The VPN permission was likely revoked.")
        tunInterface = descriptor
        Log.i(TAG, "VpnService establish returned fd=${descriptor.fd}")

        val summary = buildString {
            append("TUN interface established on fd=${descriptor.fd} with route set ")
            append(
                manifest.routes.joinToString { route ->
                    "${route.address}/${route.prefixLength}"
                }.ifBlank { "none" },
            )
            if (manifest.dnsServers.isNotEmpty()) {
                append(". DNS=")
                append(manifest.dnsServers.joinToString())
            }
        }

        return TunnelTunHandle(
            fd = descriptor.fd,
            summary = summary,
        )
    }

    override fun protectFd(fd: Int): Boolean = protect(fd)

    override fun protectSocket(socket: Socket): Boolean = protect(socket)

    override fun closeTunInterface() {
        Log.i(TAG, "closeTunInterface")
        runCatching {
            tunInterface?.close()
        }
        tunInterface = null
    }

    private fun startTunnel(
        profile: TunnelProfile,
        config: RenderedTunnelConfig,
    ) {
        if (snapshotFlow.value.phase == TunnelPhase.Connecting || snapshotFlow.value.phase == TunnelPhase.Connected) {
            return
        }
        activeConfig = config
        activeBackend = config.backend
        Log.i(TAG, "startTunnel profile=${profile.name}")

        snapshotFlow.value = TunnelRuntimeSnapshot(
            phase = TunnelPhase.Connecting,
            activeProfileName = profile.name,
            detail = when (config.backend) {
                TunnelRuntimeBackend.Xray -> "Starting Xray-backed runtime with the Android VpnService TUN data plane."
                TunnelRuntimeBackend.Singbox -> "Starting libbox-backed sing-box runtime with a real Android TUN data plane."
            },
            renderedConfigPreview = config.json.take(220),
        )

        serviceScope.launch {
            val runtimeSnapshot = when (config.backend) {
                TunnelRuntimeBackend.Xray -> xrayRuntime.start(profile = profile, config = config)
                TunnelRuntimeBackend.Singbox -> singboxRuntime.start(profile = profile, config = config)
            }
            Log.i(TAG, "runtime returned phase=${runtimeSnapshot.phase} detail=${runtimeSnapshot.detail}")
            if (runtimeSnapshot.phase != TunnelPhase.Connected) {
                activeConfig = null
                activeBackend = null
                closeTunInterface()
            }
            snapshotFlow.value = runtimeSnapshot
        }
    }

    private fun stopTunnel() {
        if (snapshotFlow.value.phase == TunnelPhase.Disconnected || snapshotFlow.value.phase == TunnelPhase.Disconnecting) {
            return
        }
        Log.i(TAG, "stopTunnel")

        snapshotFlow.value = snapshotFlow.value.copy(
            phase = TunnelPhase.Disconnecting,
            detail = "Stopping Android TUN interface.",
        )

        serviceScope.launch {
            snapshotFlow.value = when (activeBackend) {
                TunnelRuntimeBackend.Xray -> xrayRuntime.stop()
                TunnelRuntimeBackend.Singbox, null -> singboxRuntime.stop()
            }
            activeConfig = null
            activeBackend = null
            closeTunInterface()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun ensureForegroundService() {
        val notificationManager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Tunnel status",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Keeps the Android VPN tunnel alive while it is active."
                setShowBadge(false)
            }
            notificationManager?.createNotificationChannel(channel)
        }
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification(),
            TunnelForegroundServiceType.resolve(Build.VERSION.SDK_INT),
        )
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("vless-tun")
            .setContentText("Android VPN runtime is active.")
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun collectRoutePrefixes(iterator: RoutePrefixIterator): List<RoutePrefix> {
        val values = mutableListOf<RoutePrefix>()
        while (iterator.hasNext()) {
            values += iterator.next()
        }
        return values
    }

    private fun collectStrings(iterator: StringIterator): List<String> {
        val values = mutableListOf<String>()
        while (iterator.hasNext()) {
            values += iterator.next()
        }
        return values
    }

    private fun currentUnderlyingNetworks(): Array<Network>? {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return null
        val networks = connectivity.allNetworks.filter { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@filter false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        return networks.takeIf(List<Network>::isNotEmpty)?.toTypedArray()
    }

    private val StringBox.value: String
        get() = getValue()

    private companion object {
        const val TAG = "TunnelVpnService"
        const val NOTIFICATION_CHANNEL_ID = "vless_tun_runtime"
        const val NOTIFICATION_ID = 1001
    }
}
