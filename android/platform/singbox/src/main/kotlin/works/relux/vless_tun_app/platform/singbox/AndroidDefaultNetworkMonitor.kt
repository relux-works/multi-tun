package works.relux.vless_tun_app.platform.singbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

internal class AndroidDefaultNetworkMonitor(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val connectivity =
        appContext.getSystemService(ConnectivityManager::class.java)
            ?: error("ConnectivityManager is unavailable.")
    private val mainHandler = Handler(Looper.getMainLooper())
    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .build()

    @Volatile
    private var defaultNetwork: Network? = null

    @Volatile
    private var interfaceListener: InterfaceUpdateListener? = null

    @Volatile
    private var started = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            defaultNetwork = network
            dispatchUpdate(network)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities,
        ) {
            if (defaultNetwork == network) {
                dispatchUpdate(network)
            }
        }

        override fun onLinkPropertiesChanged(
            network: Network,
            linkProperties: LinkProperties,
        ) {
            if (defaultNetwork == network) {
                dispatchUpdate(network)
            }
        }

        override fun onLost(network: Network) {
            if (defaultNetwork == network) {
                defaultNetwork = null
                dispatchUpdate(null)
            }
        }
    }

    fun start() {
        if (started) {
            return
        }
        started = true
        defaultNetwork = connectivity.activeNetwork
        connectivity.registerBestMatchingNetworkCallback(request, callback, mainHandler)
        dispatchUpdate(defaultNetwork)
    }

    fun stop() {
        if (!started) {
            return
        }
        started = false
        runCatching {
            connectivity.unregisterNetworkCallback(callback)
        }
        defaultNetwork = null
    }

    fun require(): Network {
        return defaultNetwork
            ?: connectivity.activeNetwork
            ?: error("No default Android network is available for tunnel bootstrap.")
    }

    fun setListener(listener: InterfaceUpdateListener?) {
        interfaceListener = listener
        dispatchUpdate(defaultNetwork)
    }

    private fun dispatchUpdate(network: Network?) {
        val listener = interfaceListener ?: return
        if (network == null) {
            listener.updateDefaultInterface("", -1, false, false)
            return
        }
        val interfaceName = connectivity.getLinkProperties(network)?.interfaceName ?: return
        publishWhenInterfaceReady(
            listener = listener,
            interfaceName = interfaceName,
            attempt = 0,
        )
    }

    private fun publishWhenInterfaceReady(
        listener: InterfaceUpdateListener,
        interfaceName: String,
        attempt: Int,
    ) {
        val interfaceIndex = runCatching {
            NetworkInterface.getByName(interfaceName)?.index ?: -1
        }.getOrDefault(-1)
        if (interfaceIndex >= 0 || attempt >= MAX_INTERFACE_LOOKUP_ATTEMPTS) {
            listener.updateDefaultInterface(interfaceName, interfaceIndex, false, false)
            return
        }
        mainHandler.postDelayed(
            {
                publishWhenInterfaceReady(
                    listener = listener,
                    interfaceName = interfaceName,
                    attempt = attempt + 1,
                )
            },
            INTERFACE_LOOKUP_RETRY_MS,
        )
    }

    private companion object {
        const val MAX_INTERFACE_LOOKUP_ATTEMPTS = 10
        const val INTERFACE_LOOKUP_RETRY_MS = 100L
    }
}
