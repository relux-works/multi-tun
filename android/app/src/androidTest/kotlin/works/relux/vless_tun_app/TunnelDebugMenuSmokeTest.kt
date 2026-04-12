package works.relux.vless_tun_app

import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Before
import org.junit.Test
import works.relux.vless_tun_app.pages.TunnelHomePage

class TunnelDebugMenuSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @Before
    fun seedCrashHistory() {
        TunnelDeviceTestHarness.clearCrashLogs()
        TunnelDeviceTestHarness.seedCrashLog(
            exceptionClass = "java.lang.IllegalStateException",
            exceptionMessage = "Seeded debug menu crash",
        )
    }

    @Test
    fun debugMenuOpensAndShowsSeededCrash() {
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
            freshProcess = true,
        )
        screenshot(1, "app_launched")

        val page = TunnelHomePage(device)
            .waitForReady()
            .openDebugMenu()
        screenshot(2, "debug_menu_app_info")

        page.openDebugMenuExceptionsTab()
            .waitForVisibleText("Seeded debug menu crash", timeout = 5_000)
        screenshot(3, "debug_menu_exceptions")
    }
}
