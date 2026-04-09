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

    val snapshots: StateFlow<TunnelRuntimeSnapshot> = snapshotFlow.asStateFlow()

    private var serviceConnection: ServiceConnection? = null
    private var binder: TunnelVpnService.LocalBinder? = null

    fun prepareVpnPermissionIntent(): Intent? {
        val context = appContext ?: return null
        return VpnService.prepare(context)
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
        ensureBound(context) { connectedBinder ->
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
        binder = null
        serviceConnection = null
        scope.cancel()
    }

    private fun ensureBound(
        context: Context,
        onReady: (TunnelVpnService.LocalBinder) -> Unit,
    ) {
        binder?.let(onReady)
        if (binder != null) {
            return
        }

        val intent = Intent(context, TunnelVpnService::class.java)
        ContextCompat.startForegroundService(context, intent)
        Log.i(TAG, "binding TunnelVpnService")

        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val tunnelBinder = service as? TunnelVpnService.LocalBinder ?: return
                binder = tunnelBinder
                Log.i(TAG, "TunnelVpnService connected")
                scope.launch {
                    tunnelBinder.snapshots().collect { snapshot ->
                        Log.i(TAG, "snapshot phase=${snapshot.phase} detail=${snapshot.detail}")
                        snapshotFlow.value = snapshot
                    }
                }
                onReady(tunnelBinder)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                binder = null
                Log.i(TAG, "TunnelVpnService disconnected")
                snapshotFlow.value = TunnelRuntimeSnapshot(
                    phase = TunnelPhase.Disconnected,
                    detail = "TunnelVpnService disconnected.",
                )
            }
        }

        serviceConnection = connection
        context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }

    private companion object {
        const val TAG = "TunnelServiceConnector"
    }
}
