package works.relux.vless_tun_app

import android.util.Log
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.uitesttools.uitest.pageobject.BaseUiTestSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags

@RunWith(AndroidJUnit4::class)
class TunnelInlineXhttpBypassSmokeTest : BaseUiTestSuite() {
    override val packageName = "works.relux.android.vlesstun.app"

    @get:Rule
    val composeRule = createEmptyComposeRule()

    @Before
    override fun setUp() {
        super.setUp()
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
    }

    @Test
    fun xhttpTunnelKeepsBypassTrafficDirect() {
        val directRoutedIp = IpifyProbeClient.probe(ROUTED_HOST)
        val directBypassIp = IpifyProbeClient.probe(BYPASS_HOST)
        logProbe("direct_route", directRoutedIp)
        logProbe("direct_bypass", directBypassIp)

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
            stringExtras = mapOf(
                UiTestLaunchContract.EXTRA_ACTION to UiTestLaunchContract.ACTION_OPEN_EDIT_SELECTED_EDITOR,
                UiTestLaunchContract.EXTRA_LAYOUT to UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP,
            ),
        )
        screenshot(1, "xhttp_editor_opened")

        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_ROUTE_MASKS_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement("ipify.org")
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_BYPASS_MASKS_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement(BYPASS_HOST)
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SAVE_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = EDITOR_TIMEOUT) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }
        screenshot(2, "xhttp_bypass_policy_saved")

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        screenshot(3, "xhttp_connect_requested")
        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )
        waitForTerminalPhase(CONNECT_TIMEOUT)
        val phaseText = semanticsText(TunnelHomeTags.STATUS_PHASE)
        val detailText = semanticsText(TunnelHomeTags.STATUS_DETAIL)
        assertEquals(
            "Expected XHTTP bypass profile to connect successfully. phase='$phaseText' detail='$detailText'",
            TunnelPhase.Connected.name,
            phaseText,
        )
        waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)
        screenshot(4, "xhttp_tunnel_connected")

        val tunneledRoutedIp = IpifyProbeClient.probe(ROUTED_HOST)
        val bypassAfterConnectIp = IpifyProbeClient.probe(BYPASS_HOST)
        logProbe("connected_route", tunneledRoutedIp)
        logProbe("connected_bypass", bypassAfterConnectIp)

        assertNotEquals(
            "Expected routed host $ROUTED_HOST to switch to tunnel egress after connect.",
            directRoutedIp,
            tunneledRoutedIp,
        )
        assertEquals(
            "Expected bypass host $BYPASS_HOST to stay on direct egress while the broader ipify.org suffix is routed.",
            directBypassIp,
            bypassAfterConnectIp,
        )
        assertNotEquals(
            "Expected bypass host $BYPASS_HOST to override the routed ipify.org suffix.",
            tunneledRoutedIp,
            bypassAfterConnectIp,
        )
        screenshot(5, "xhttp_bypass_verified")

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = DISCONNECT_TIMEOUT) {
            semanticsText(TunnelHomeTags.STATUS_PHASE) == TunnelPhase.Disconnected.name
        }
        screenshot(6, "xhttp_tunnel_disconnected")
    }

    private fun logProbe(label: String, value: String) {
        val message = "XHTTP_BYPASS_${label.uppercase()}=$value"
        Log.i(TAG, message)
        println(message)
    }

    private fun waitForTerminalPhase(timeout: Long) {
        composeRule.waitUntil(timeoutMillis = timeout) {
            when (semanticsText(TunnelHomeTags.STATUS_PHASE)) {
                TunnelPhase.Connected.name,
                TunnelPhase.Error.name,
                TunnelPhase.Disconnected.name,
                -> true
                else -> false
            }
        }
    }

    private fun waitForDetailContains(
        text: String,
        timeout: Long,
    ) {
        composeRule.waitUntil(timeoutMillis = timeout) {
            semanticsText(TunnelHomeTags.STATUS_DETAIL).contains(text, ignoreCase = true)
        }
    }

    private fun semanticsText(tag: String): String {
        val node = composeRule
            .onAllNodesWithTag(tag, useUnmergedTree = true)
            .fetchSemanticsNodes()
            .firstOrNull()
            ?: return ""
        return node.config.getOrElse(SemanticsProperties.Text) { emptyList<AnnotatedString>() }
            .joinToString(separator = "") { annotated: AnnotatedString -> annotated.text }
    }

    private companion object {
        const val TAG = "TunnelXhttpBypassSmoke"
        const val ROUTED_HOST = "api.ipify.org"
        const val BYPASS_HOST = "api64.ipify.org"
        const val EDITOR_TIMEOUT = 5_000L
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val DISCONNECT_TIMEOUT = 10_000L
    }
}
