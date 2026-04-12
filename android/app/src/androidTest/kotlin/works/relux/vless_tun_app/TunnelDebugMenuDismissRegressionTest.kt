package works.relux.vless_tun_app

import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Test
import works.relux.vless_tun_app.pages.TunnelHomePage

class TunnelDebugMenuDismissRegressionTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @Test
    fun debugMenuStaysVisibleAfterEightFastHeaderTaps() {
        assertDebugMenuSurvivesEighthTap(
            intervalMillis = 150,
            screenshotLabel = "debug_menu_still_visible_after_eight_fast_taps",
        )
    }

    @Test
    fun debugMenuStaysVisibleAfterEightCalmHeaderTaps() {
        assertDebugMenuSurvivesEighthTap(
            intervalMillis = 400,
            screenshotLabel = "debug_menu_still_visible_after_eight_calm_taps",
        )
    }

    private fun assertDebugMenuSurvivesEighthTap(
        intervalMillis: Long,
        screenshotLabel: String,
    ) {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
            freshProcess = true,
        )
        screenshot(1, "app_launched")

        TunnelHomePage(device)
            .waitForReady()
            .tapTopBar(times = 8, intervalMillis = intervalMillis)
            .waitForDebugMenu(timeout = 5_000)
            .assertDebugMenuVisible()

        screenshot(2, screenshotLabel)
    }
}
