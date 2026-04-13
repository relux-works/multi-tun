package works.relux.vless_tun_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelRelaunchSyncSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @Before
    override fun setUp() {
        super.setUp()
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
    }

    @Test
    fun relaunchKeepsConnectedStateInUi() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )

        val firstLaunchPage = TunnelHomePage(device).waitForReady()
        firstLaunchPage.tapPrimary()
        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )
        firstLaunchPage.waitForPhase(TunnelPhase.Connected, CONNECT_TIMEOUT)
        firstLaunchPage.waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)
        screenshot(1, "connected_before_relaunch")

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )

        val relaunchedPage = TunnelHomePage(device).waitForReady()
        relaunchedPage.waitForPhase(TunnelPhase.Connected, RELAUNCH_SYNC_TIMEOUT)
        relaunchedPage.waitForDetailContains("TUN interface established", RELAUNCH_SYNC_TIMEOUT)
        screenshot(2, "connected_after_relaunch")

        relaunchedPage.tapPrimary()
        relaunchedPage.waitForPhase(TunnelPhase.Disconnected, DISCONNECT_TIMEOUT)
    }

    private companion object {
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val RELAUNCH_SYNC_TIMEOUT = 10_000L
        const val DISCONNECT_TIMEOUT = 10_000L
    }
}
