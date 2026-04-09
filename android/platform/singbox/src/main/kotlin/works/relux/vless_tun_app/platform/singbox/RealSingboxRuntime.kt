package works.relux.vless_tun_app.platform.singbox

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import android.util.Log
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface as JvmNetworkInterface
import java.security.KeyStore
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot

class RealSingboxRuntime(
    private val host: SingboxRuntimeHost,
) : CommandServerHandler, PlatformInterface {
    private var commandServer: CommandServer? = null
    private val defaultNetworkMonitor = AndroidDefaultNetworkMonitor(host.context)
    private val localDnsTransport = AndroidLocalDnsTransport(defaultNetworkMonitor)
    private var lastProfile: TunnelProfile? = null
    private var lastConfig: RenderedTunnelConfig? = null
    private var lastTunSummary = "TUN interface not established yet."
    private var lastNotificationSummary = ""
    private var tunOpened = false

    suspend fun start(
        profile: TunnelProfile,
        config: RenderedTunnelConfig,
    ): TunnelRuntimeSnapshot = withContext(Dispatchers.IO) {
        Log.i(TAG, "start profile=${profile.name} endpoint=${profile.host}:${profile.port} transport=${profile.transport} security=${profile.security}")
        lastProfile = profile
        lastConfig = config
        lastTunSummary = "TUN interface not established yet."
        lastNotificationSummary = ""
        tunOpened = false

        runCatching {
            defaultNetworkMonitor.start()
            Libbox.checkConfig(config.json)
            Log.i(TAG, "libbox config validated")
            val server = ensureCommandServer()
            server.startOrReloadService(config.json, OverrideOptions().apply {
                setAutoRedirect(false)
            })
            Log.i(TAG, "libbox service started or reloaded, waiting for tun")
            waitForTunOpen()
        }.fold(
            onSuccess = { tunWasOpened ->
                if (!tunWasOpened) {
                    host.closeTunInterface()
                    return@fold TunnelRuntimeSnapshot(
                        phase = TunnelPhase.Error,
                        activeProfileName = profile.name,
                        detail = "sing-box returned without opening the Android TUN interface.",
                        renderedConfigPreview = config.json.take(220),
                    )
                }
                TunnelRuntimeSnapshot(
                    phase = TunnelPhase.Connected,
                    activeProfileName = profile.name,
                    detail = buildString {
                        append(lastTunSummary)
                        if (lastNotificationSummary.isNotBlank()) {
                            append(' ')
                            append(lastNotificationSummary)
                        }
                    }.trim(),
                    renderedConfigPreview = config.json.take(220),
                )
            },
            onFailure = { error ->
                Log.e(TAG, "start failed", error)
                host.closeTunInterface()
                closeCommandServer()
                runCatching {
                    defaultNetworkMonitor.stop()
                }
                TunnelRuntimeSnapshot(
                    phase = TunnelPhase.Error,
                    activeProfileName = profile.name,
                    detail = error.message ?: "Failed to start libbox-backed sing-box runtime.",
                    renderedConfigPreview = config.json.take(220),
                )
            },
        )
    }

    suspend fun stop(): TunnelRuntimeSnapshot = withContext(Dispatchers.IO) {
        runCatching { commandServer?.closeService() }
        closeCommandServer()
        runCatching {
            defaultNetworkMonitor.stop()
        }
        host.closeTunInterface()
        lastProfile = null
        lastConfig = null
        tunOpened = false
        TunnelRuntimeSnapshot(
            phase = TunnelPhase.Disconnected,
            detail = "sing-box tunnel stopped.",
        )
    }

    override fun getSystemProxyStatus(): SystemProxyStatus? = null

    override fun serviceReload() {
        val config = lastConfig ?: return
        ensureCommandServer().startOrReloadService(config.json, OverrideOptions().apply {
            setAutoRedirect(false)
        })
    }

    override fun serviceStop() {
        host.closeTunInterface()
    }

    override fun setSystemProxyEnabled(isEnabled: Boolean) {
    }

    override fun triggerNativeCrash() {
        Libbox.triggerGoPanic()
    }

    override fun writeDebugMessage(message: String) {
        lastNotificationSummary = "sing-box: $message"
        Log.i(TAG, "libbox: $message")
    }

    override fun autoDetectInterfaceControl(fd: Int) {
        Log.i(TAG, "autoDetectInterfaceControl fd=$fd")
        if (!host.protectFd(fd)) {
            error("VpnService.protect(fd) returned false for fd=$fd")
        }
    }

    override fun clearDNSCache() {
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        defaultNetworkMonitor.setListener(null)
    }

    override fun closeNeighborMonitor(listener: NeighborUpdateListener) {
    }

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        val connectivity = host.context.getSystemService(ConnectivityManager::class.java)
        val owner = ConnectionOwner()
        if (connectivity == null) {
            return owner
        }
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        if (uid == Process.INVALID_UID) {
            return owner
        }
        val packageNames = host.context.packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        owner.setUserId(uid)
        owner.setUserName(packageNames.firstOrNull().orEmpty())
        owner.setAndroidPackageNames(StringArray(packageNames.iterator()))
        return owner
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val connectivity = host.context.getSystemService(ConnectivityManager::class.java)
            ?: return InterfaceArray(emptyList<NetworkInterface>().iterator())
        val networkInterfaces = JvmNetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        val interfaces = mutableListOf<NetworkInterface>()

        connectivity.allNetworks.forEach { network ->
            val linkProperties = connectivity.getLinkProperties(network) ?: return@forEach
            val networkCapabilities = connectivity.getNetworkCapabilities(network) ?: return@forEach
            val networkInterface = networkInterfaces.find { it.name == linkProperties.interfaceName } ?: return@forEach

            val item = NetworkInterface()
            item.setName(linkProperties.interfaceName)
            item.setIndex(networkInterface.index)
            item.setType(
                when {
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                },
            )
            runCatching {
                item.setMTU(networkInterface.mtu)
            }
            item.setDNSServer(StringArray(linkProperties.dnsServers.mapNotNull { it.hostAddress }.iterator()))
            item.setAddresses(
                StringArray(
                    networkInterface.interfaceAddresses
                        .mapNotNull { address -> runCatching { address.toPrefix() }.getOrNull() }
                        .iterator(),
                ),
            )
            item.setFlags(networkInterface.flags)
            item.setMetered(
                !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            )
            interfaces.add(item)
        }

        return InterfaceArray(interfaces.iterator())
    }

    override fun includeAllNetworks(): Boolean = false

    override fun localDNSTransport(): LocalDNSTransport = localDnsTransport

    override fun openTun(options: TunOptions): Int {
        Log.i(TAG, "openTun requested by libbox")
        val result = host.openTun(options)
        tunOpened = true
        lastTunSummary = result.summary
        Log.i(TAG, "openTun completed fd=${result.fd}")
        return result.fd
    }

    override fun readWIFIState(): WIFIState? {
        val wifiManager = host.context.getSystemService(WifiManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val info = wifiManager.connectionInfo ?: return null
        var ssid = info.ssid ?: return null
        if (ssid == "<unknown ssid>") {
            return WIFIState("", "")
        }
        if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length - 1)
        }
        return WIFIState(ssid, info.bssid.orEmpty())
    }

    override fun registerMyInterface(name: String?) {
    }

    override fun sendNotification(notification: Notification) {
        lastNotificationSummary = listOf(
            notification.getTitle(),
            notification.getSubtitle(),
            notification.getBody(),
        ).filter { it.isNotBlank() }.joinToString(" | ")
        if (lastNotificationSummary.isNotBlank()) {
            Log.i(TAG, lastNotificationSummary)
        }
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        defaultNetworkMonitor.setListener(listener)
    }

    override fun startNeighborMonitor(listener: NeighborUpdateListener) {
    }

    override fun systemCertificates(): StringIterator {
        val certificates = mutableListOf<String>()
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val certificate = keyStore.getCertificate(aliases.nextElement())
                certificates += buildString {
                    append("-----BEGIN CERTIFICATE-----\n")
                    append(Base64.getEncoder().encodeToString(certificate.encoded))
                    append("\n-----END CERTIFICATE-----")
                }
            }
        }
        return StringArray(certificates.iterator())
    }

    override fun underNetworkExtension(): Boolean = false

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    private fun ensureCommandServer(): CommandServer {
        val existing = commandServer
        if (existing != null) {
            return existing
        }
        return CommandServer(this, this).also { server ->
            server.start()
            Log.i(TAG, "CommandServer started")
            commandServer = server
        }
    }

    private fun closeCommandServer() {
        Log.i(TAG, "CommandServer closing")
        runCatching { commandServer?.close() }
        commandServer = null
    }

    private suspend fun waitForTunOpen(): Boolean {
        repeat(TUN_OPEN_ATTEMPTS) {
            if (tunOpened) {
                return true
            }
            delay(TUN_OPEN_POLL_MS)
        }
        return false
    }

    private class InterfaceArray(
        private val iterator: Iterator<NetworkInterface>,
    ) : NetworkInterfaceIterator {
        override fun hasNext(): Boolean = iterator.hasNext()

        override fun next(): NetworkInterface = iterator.next()
    }

    private class StringArray(
        private val iterator: Iterator<String>,
    ) : StringIterator {
        override fun hasNext(): Boolean = iterator.hasNext()

        override fun len(): Int = 0

        override fun next(): String = iterator.next()
    }

    private fun InterfaceAddress.toPrefix(): String = if (address is Inet6Address) {
        "${Inet6Address.getByAddress(address.address).hostAddress}/$networkPrefixLength"
    } else {
        "${address.hostAddress}/$networkPrefixLength"
    }

    private val JvmNetworkInterface.flags: Int
        get() = runCatching {
            val getFlagsMethod = JvmNetworkInterface::class.java.getDeclaredMethod("getFlags")
            getFlagsMethod.invoke(this) as Int
        }.getOrElse {
            var flags = 0
            if (isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
            if (isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
            if (supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
            if (isUp) flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            flags
        }

    private companion object {
        const val TAG = "RealSingboxRuntime"
        const val TUN_OPEN_ATTEMPTS = 40
        const val TUN_OPEN_POLL_MS = 100L
    }
}
