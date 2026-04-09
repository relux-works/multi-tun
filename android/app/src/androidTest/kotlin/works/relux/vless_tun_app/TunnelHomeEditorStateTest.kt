package works.relux.vless_tun_app

import android.content.Intent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags

@RunWith(AndroidJUnit4::class)
class TunnelHomeEditorStateTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)

    @get:Rule
    val composeRule = createEmptyComposeRule()

    @Before
    fun launchActivity() {
        val targetContext = instrumentation.targetContext
        val packageName = targetContext.packageName
        val component = targetContext.packageManager
            .getLaunchIntentForPackage(packageName)
            ?.component
            ?.flattenToString()
            ?: "$packageName/${MainActivity::class.java.name}"
        val command = buildString {
            append("am start -W -n ")
            append(component)
            append(" --es ")
            append(UiTestLaunchContract.EXTRA_ACTION)
            append(' ')
            append(UiTestLaunchContract.ACTION_OPEN_CREATE_EDITOR)
            append(" --es ")
            append(UiTestLaunchContract.EXTRA_LAYOUT)
            append(' ')
            append(UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP)
        }
        device.executeShellCommand(command)
        instrumentation.waitForIdleSync()
        check(device.wait(Until.hasObject(By.pkg(packageName).depth(0)), 5_000)) {
            "Main activity did not become visible after shell launch."
        }
    }

    @Test
    fun savingSubscriptionUrlUpdatesHomeState() {
        val updatedSourceUrl = TunnelDeviceTestHarness.sourceUrlOrDefault("https://updated-subscription.example/path")
        val updatedHostMarker = updatedSourceUrl
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore('/')
            .ifBlank { updatedSourceUrl }

        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
            .assertIsDisplayed()

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SOURCE_URL_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement(updatedSourceUrl)

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SAVE_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }

        composeRule.onNodeWithTag(TunnelHomeTags.STATUS_SOURCE_SUMMARY, useUnmergedTree = true)
            .performScrollTo()
            .assertTextContains("Subscription URL:", substring = true)
            .assertTextContains(updatedHostMarker, substring = true)

        composeRule.onNodeWithTag(TunnelHomeTags.STATUS_ENDPOINT, useUnmergedTree = true)
            .performScrollTo()
            .assertTextContains("Resolved on connect", substring = true)
    }
}
