package works.relux.vless_tun_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelUnsupportedTransportSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @Before
    override fun setUp() {
        super.setUp()
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
    }

    @Test
    fun unsupportedXhttpSourceFailsFastOnUi() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
        )

        val page = TunnelHomePage(device).waitForReady()
        page.tapPrimary()
        page.waitForPhase(TunnelPhase.Error, ERROR_TIMEOUT)
        page.waitForDetailContains("Unsupported VLESS transport 'xhttp'", ERROR_TIMEOUT)
        screenshot(1, "unsupported_xhttp_error")
    }

    private companion object {
        const val ERROR_TIMEOUT = 10_000L
    }
}
