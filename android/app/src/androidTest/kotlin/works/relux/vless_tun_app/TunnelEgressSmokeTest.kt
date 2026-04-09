package works.relux.vless_tun_app

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.pages.ObserverPage
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelEgressSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.vless_tun_app"

    private lateinit var observerBootstrapIp: String

    @Before
    override fun setUp() {
        super.setUp()
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
        observerBootstrapIp = TunnelDeviceTestHarness.observerBootstrapIp()
    }

    @Test
    fun egressChangesAfterConnect() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = OBSERVER_PACKAGE,
            launchTimeout = launchTimeout,
            freshProcess = true,
            stringExtras = mapOf(
                OBSERVER_BOOTSTRAP_EXTRA to observerBootstrapIp,
            ),
        )
        screenshot(1, "observer_app_launched")

        val observerPage = ObserverPage(device).waitForReady(launchTimeout)
        observerPage.waitForResult(EGRESS_TIMEOUT)
        val directText = observerPage.resultText()
        logEgress("direct", directText)
        screenshot(2, "observer_direct_egress_captured")

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )
        screenshot(3, "app_launched")

        val page = TunnelHomePage(device).waitForReady()
        page.tapPrimary()
        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )
        page.waitForPhase(TunnelPhase.Connected, CONNECT_TIMEOUT)
        page.waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)
        screenshot(4, "tunnel_connected")

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = OBSERVER_PACKAGE,
            launchTimeout = launchTimeout,
            freshProcess = true,
            stringExtras = mapOf(
                OBSERVER_BOOTSTRAP_EXTRA to observerBootstrapIp,
            ),
        )
        screenshot(5, "observer_relaunched_under_tunnel")

        observerPage.waitForReady(launchTimeout)
        observerPage.waitForResult(EGRESS_TIMEOUT)
        val tunneledText = observerPage.resultText()
        logEgress("tunneled", tunneledText)
        screenshot(6, "observer_tunneled_egress_captured")

        assertNotEquals(
            "Expected tunneled egress to differ from direct egress.",
            directText,
            tunneledText,
        )

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )
        page.tapPrimary()
        page.waitForPhase(TunnelPhase.Disconnected, DISCONNECT_TIMEOUT)
        screenshot(7, "tunnel_disconnected")
    }

    private companion object {
        const val TAG = "TunnelEgressSmokeTest"
        const val OBSERVER_PACKAGE = "works.relux.vless_tun_observer"
        const val OBSERVER_BOOTSTRAP_EXTRA = "observer_bootstrap_ip"
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val DISCONNECT_TIMEOUT = 10_000L
        const val EGRESS_TIMEOUT = 20_000L
    }

    private fun logEgress(stage: String, value: String) {
        val message = "EGRESS_${stage.uppercase()}=$value"
        Log.i(TAG, message)
        println(message)
    }
}
