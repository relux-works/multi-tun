package works.relux.vless_tun_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelConnectSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.vless_tun_app"

    @Before
    override fun setUp() {
        super.setUp()
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
    }

    @Test
    fun tunnelConnectsAndDisconnects() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )
        screenshot(1, "app_launched")

        val page = TunnelHomePage(device).waitForReady()
        page.tapPrimary()
        screenshot(2, "connect_requested")

        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )

        page.waitForPhase(TunnelPhase.Connected, CONNECT_TIMEOUT)
        page.waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)
        screenshot(3, "tunnel_connected")

        page.tapPrimary()
        page.waitForPhase(TunnelPhase.Disconnected, DISCONNECT_TIMEOUT)
        screenshot(4, "tunnel_disconnected")
    }

    private companion object {
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val DISCONNECT_TIMEOUT = 10_000L
    }
}
