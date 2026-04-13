package works.relux.vless_tun_app.platform.xray

import android.content.Context
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeManifest
import works.relux.vless_tun_app.core.runtime.TunnelTunHandle

interface XrayRuntimeHost {
    val context: Context

    fun openTun(manifest: TunnelRuntimeManifest): TunnelTunHandle

    fun protectFd(fd: Int): Boolean

    fun closeTunInterface()
}
