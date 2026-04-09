package works.relux.vless_tun_app.platform.singbox

import android.content.Context
import io.nekohasekai.libbox.TunOptions
import java.net.Socket

data class TunOpenResult(
    val fd: Int,
    val summary: String,
)

interface SingboxRuntimeHost {
    val context: Context

    fun openTun(options: TunOptions): TunOpenResult

    fun protectFd(fd: Int): Boolean

    fun protectSocket(socket: Socket): Boolean

    fun closeTunInterface()
}
