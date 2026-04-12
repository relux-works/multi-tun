package works.relux.vless_tun_app.platform.vpnservice

import android.content.pm.ServiceInfo
import junit.framework.TestCase.assertEquals
import org.junit.Test

class TunnelForegroundServiceTypeTest {
    @Test
    fun `uses no explicit type before android 14`() {
        assertEquals(0, TunnelForegroundServiceType.resolve(33))
    }

    @Test
    fun `uses system exempted type on android 14 and newer`() {
        val expected = ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED

        assertEquals(expected, TunnelForegroundServiceType.resolve(34))
        assertEquals(expected, TunnelForegroundServiceType.resolve(35))
    }
}
