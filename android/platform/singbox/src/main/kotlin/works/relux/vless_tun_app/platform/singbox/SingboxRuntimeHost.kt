package works.relux.vless_tun_app.platform.singbox

import android.content.Context
import io.nekohasekai.libbox.TunOptions
import java.net.Socket
import works.relux.vless_tun_app.core.runtime.TunnelTunHandle

interface SingboxRuntimeHost {
    val context: Context

    fun openTun(options: TunOptions): TunnelTunHandle

    fun protectFd(fd: Int): Boolean

    fun protectSocket(socket: Socket): Boolean

    fun closeTunInterface()
}
