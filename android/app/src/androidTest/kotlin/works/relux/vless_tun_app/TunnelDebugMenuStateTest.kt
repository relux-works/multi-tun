package works.relux.vless_tun_app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelDebugMenuStateTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)
    private val packageName = "works.relux.android.vlesstun.app"

    @Before
    fun launchActivityWithSeededCrash() {
        TunnelDeviceTestHarness.clearCrashLogs()
        TunnelDeviceTestHarness.seedCrashLog(
            exceptionClass = "java.lang.IllegalArgumentException",
            exceptionMessage = "State-test seeded crash entry",
        )
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = 5_000,
            freshProcess = true,
        )
    }

    @Test
    fun debugMenuShowsAppInfoAndSeededCrashHistory() {
        val page = TunnelHomePage(device)
            .waitForReady()
            .openDebugMenu()

        page.waitForVisibleText("Version", timeout = 5_000)
            .waitForVisibleText("Android", timeout = 5_000)
            .openDebugMenuExceptionsTab()
            .waitForVisibleText("State-test seeded crash entry", timeout = 5_000)
            .waitForVisibleText("java.lang.IllegalArgumentException", timeout = 5_000)
    }
}
