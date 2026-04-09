package works.relux.vless_tun_app

import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Test
import works.relux.vless_tun_app.pages.TunnelHomePage

class TunnelHomeSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.vless_tun_app"

    @Test
    fun tunnelHomeLoads() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )
        screenshot(1, "app_launched")

        val page = TunnelHomePage(device).waitForReady()
        screenshot(2, "tunnel_home_visible")

        requireNotNull(page.title) {
            "Tunnel Home title was not found"
        }
    }
}
