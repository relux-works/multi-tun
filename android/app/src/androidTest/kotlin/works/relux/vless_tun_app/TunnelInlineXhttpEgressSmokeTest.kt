package works.relux.vless_tun_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Ignore
import org.junit.runner.RunWith

@Ignore("Blocked until Android gets an Xray-backed runtime path with real XHTTP support.")
@RunWith(AndroidJUnit4::class)
class TunnelInlineXhttpEgressSmokeTest : AbstractTunnelSourceEgressSmokeTest()
