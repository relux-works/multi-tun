package works.relux.vless_tun_app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.assertTextContains
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags

@RunWith(AndroidJUnit4::class)
class TunnelHomeEditFlowTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)

    @get:Rule
    val composeRule = createEmptyComposeRule()

    @Before
    fun launchActivity() {
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.sourceUrlOrDefault("https://seeded-subscription.example/path"),
        )
        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = instrumentation.targetContext.packageName,
            launchTimeout = 5_000L,
            freshProcess = true,
        )
    }

    @Test
    fun tappingEditOpensDedicatedEditorScreen() {
        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()

        composeRule.onNodeWithTag(TunnelHomeTags.TUNNEL_EDIT_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()

        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_SCREEN, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isNotEmpty()
        }

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_DELETE_BUTTON, useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun deletingTunnelFromDedicatedEditorReturnsToEmptyHome() {
        composeRule.onNodeWithTag(TunnelHomeTags.TUNNEL_EDIT_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_DELETE_BUTTON, useUnmergedTree = true)
            .performClick()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_DELETE_CONFIRM_BUTTON, useUnmergedTree = true)
            .performClick()

        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_SCREEN, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }

        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.STATUS_SELECTED_TUNNEL, useUnmergedTree = true)
            .assertTextContains("No tunnels configured", substring = true)
    }
}
