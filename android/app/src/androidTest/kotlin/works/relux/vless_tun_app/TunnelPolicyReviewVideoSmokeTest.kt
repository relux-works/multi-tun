package works.relux.vless_tun_app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags
import works.relux.vless_tun_app.pages.TunnelHomePage

@RunWith(AndroidJUnit4::class)
class TunnelPolicyReviewVideoSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @get:Rule
    val composeRule = createEmptyComposeRule()

    @Test
    fun addTunnelThenConnectAndDisconnect() {
        val sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl()

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
            freshProcess = true,
            stringExtras = mapOf(
                UiTestLaunchContract.EXTRA_ACTION to UiTestLaunchContract.ACTION_OPEN_CREATE_EDITOR,
                UiTestLaunchContract.EXTRA_LAYOUT to UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP,
            ),
        )

        TunnelHomePage(device).waitForReady()
        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
            .assertIsDisplayed()
        screenshot(1, "editor_opened")

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SOURCE_URL_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement(sourceUrl)
        screenshot(2, "source_entered")

        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SAVE_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = EDITOR_TIMEOUT) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }
        screenshot(3, "tunnel_saved")

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        screenshot(4, "connect_requested")

        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )

        composeRule.waitUntil(timeoutMillis = CONNECT_TIMEOUT) {
            semanticsText(TunnelHomeTags.STATUS_PHASE) == TunnelPhase.Connected.name
        }
        composeRule.waitUntil(timeoutMillis = CONNECT_TIMEOUT) {
            semanticsText(TunnelHomeTags.STATUS_DETAIL)
                .contains("TUN interface established", ignoreCase = true)
        }
        screenshot(5, "tunnel_connected")

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = DISCONNECT_TIMEOUT) {
            semanticsText(TunnelHomeTags.STATUS_PHASE) == TunnelPhase.Disconnected.name
        }
        screenshot(6, "tunnel_disconnected")
    }

    private fun semanticsText(tag: String): String {
        val node = composeRule
            .onAllNodesWithTag(tag, useUnmergedTree = true)
            .fetchSemanticsNodes()
            .firstOrNull()
            ?: return ""
        return node.config.getOrElse(SemanticsProperties.Text) { emptyList<AnnotatedString>() }
            .joinToString(separator = "") { annotated -> annotated.text }
    }

    private companion object {
        const val EDITOR_TIMEOUT = 5_000L
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val DISCONNECT_TIMEOUT = 10_000L
    }
}
