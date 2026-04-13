package works.relux.vless_tun_app.platform.vpnservice

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeSnapshot

class TunnelServiceConnector(
    context: Context?,
) {
    private val appContext = context?.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val snapshotFlow = MutableStateFlow(TunnelRuntimeSnapshot())
    private val pendingReadyCallbacks = mutableListOf<(TunnelVpnService.LocalBinder) -> Unit>()

    val snapshots: StateFlow<TunnelRuntimeSnapshot> = snapshotFlow.asStateFlow()

    private var serviceConnection: ServiceConnection? = null
    private var binder: TunnelVpnService.LocalBinder? = null
    private var snapshotCollectionJob: Job? = null

    fun prepareVpnPermissionIntent(): Intent? {
        val context = appContext ?: return null
        return VpnService.prepare(context)
    }

    fun syncWithRunningService() {
        val context = appContext ?: return
        bind(
            context = context,
            createIfNeeded = false,
        )
    }

    fun connect(
        profile: TunnelProfile,
        config: RenderedTunnelConfig,
    ) {
        val context = appContext
        if (context == null) {
            snapshotFlow.value = TunnelRuntimeSnapshot(
                phase = TunnelPhase.Error,
                detail = "Service connector has no Android context.",
            )
            return
        }

        Log.i(TAG, "connect requested for profile=${profile.name}")
        bind(context = context, createIfNeeded = true) { connectedBinder ->
            Log.i(TAG, "service binder ready, forwarding connect")
            connectedBinder.connect(profile, config)
        }
    }

    fun disconnect() {
        binder?.disconnect()?.also {
            Log.i(TAG, "disconnect forwarded to service")
        } ?: run {
            snapshotFlow.value = snapshotFlow.value.copy(
                phase = TunnelPhase.Disconnected,
                detail = "No active TunnelVpnService binding.",
            )
        }
    }

    fun release() {
        val context = appContext
        val connection = serviceConnection
        if (context != null && connection != null) {
            runCatching {
                context.unbindService(connection)
            }
        }
        snapshotCollectionJob?.cancel()
        snapshotCollectionJob = null
        binder = null
        serviceConnection = null
        pendingReadyCallbacks.clear()
        scope.cancel()
    }

    private fun bind(
        context: Context,
        createIfNeeded: Boolean,
        onReady: ((TunnelVpnService.LocalBinder) -> Unit)? = null,
    ) {
        binder?.let { connectedBinder ->
            onReady?.invoke(connectedBinder)
        }
        if (binder != null) {
            return
        }

        if (onReady != null) {
            pendingReadyCallbacks += onReady
        }
        if (createIfNeeded) {
            ContextCompat.startForegroundService(context, Intent(context, TunnelVpnService::class.java))
        }
        if (serviceConnection != null) {
            return
        }

        val intent = Intent(context, TunnelVpnService::class.java)
        Log.i(TAG, "binding TunnelVpnService createIfNeeded=$createIfNeeded")

        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val tunnelBinder = service as? TunnelVpnService.LocalBinder ?: return
                binder = tunnelBinder
                Log.i(TAG, "TunnelVpnService connected")
                snapshotCollectionJob?.cancel()
                snapshotCollectionJob = scope.launch {
                    tunnelBinder.snapshots().collect { snapshot ->
                        Log.i(TAG, "snapshot phase=${snapshot.phase} detail=${snapshot.detail}")
                        snapshotFlow.value = snapshot
                    }
                }
                val callbacks = pendingReadyCallbacks.toList()
                pendingReadyCallbacks.clear()
                callbacks.forEach { callback ->
                    callback(tunnelBinder)
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                snapshotCollectionJob?.cancel()
                snapshotCollectionJob = null
                binder = null
                serviceConnection = null
                Log.i(TAG, "TunnelVpnService disconnected")
                snapshotFlow.value = TunnelRuntimeSnapshot(
                    phase = TunnelPhase.Disconnected,
                    detail = "TunnelVpnService disconnected.",
                )
            }
        }

        serviceConnection = connection
        val flags = if (createIfNeeded) {
            Context.BIND_AUTO_CREATE
        } else {
            0
        }
        val bound = context.bindService(intent, connection, flags)
        if (!bound) {
            Log.i(TAG, "TunnelVpnService bind skipped; no running service available.")
            serviceConnection = null
            if (createIfNeeded) {
                pendingReadyCallbacks.clear()
                snapshotFlow.value = TunnelRuntimeSnapshot(
                    phase = TunnelPhase.Error,
                    detail = "Failed to bind TunnelVpnService.",
                )
            } else {
                pendingReadyCallbacks.clear()
            }
        }
    }

    private companion object {
        const val TAG = "TunnelServiceConnector"
    }
}
