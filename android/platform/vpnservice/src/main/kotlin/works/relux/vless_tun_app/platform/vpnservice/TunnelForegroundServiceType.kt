package works.relux.vless_tun_app.platform.vpnservice

import android.content.pm.ServiceInfo
import android.os.Build

internal object TunnelForegroundServiceType {
    fun resolve(sdkInt: Int): Int {
        return if (sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
        } else {
            0
        }
    }
}
