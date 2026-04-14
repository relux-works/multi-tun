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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags
import works.relux.vless_tun_app.pages.TunnelHomePage
import works.relux.vless_tun_app.pages.ObserverPage

@RunWith(AndroidJUnit4::class)
class TunnelInlineXhttpObserverVisibilitySmokeTest : BaseUiTestSuite() {
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
    fun blacklistedObserverStaysDirectButStillSeesVpnNetworkPresence() {
        val directRouted = observeHost(ROUTED_HOST)
        screenshot(1, "observer_direct_routed_captured")

        val directBypass = observeHost(BYPASS_HOST)
        screenshot(2, "observer_direct_bypass_captured")

        assertFalse(
            "Expected routed host visibility to stay non-VPN before connect. snapshot=$directRouted",
            directRouted.vpnTransportVisible,
        )
        assertFalse(
            "Expected bypass host visibility to stay non-VPN before connect. snapshot=$directBypass",
            directBypass.vpnTransportVisible,
        )

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = packageName,
            launchTimeout = launchTimeout,
            stringExtras = mapOf(
                UiTestLaunchContract.EXTRA_ACTION to UiTestLaunchContract.ACTION_OPEN_EDIT_SELECTED_EDITOR,
                UiTestLaunchContract.EXTRA_LAYOUT to UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP,
            ),
        )
        screenshot(3, "xhttp_visibility_editor_opened")

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
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_APP_SCOPE_PICKER_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_APP_PICKER_QUERY, useUnmergedTree = true)
            .assertIsDisplayed()
            .performTextReplacement("observer")
        composeRule.waitUntil(timeoutMillis = EDITOR_TIMEOUT) {
            composeRule
                .onAllNodesWithTag(
                    TunnelHomeTags.editorAppPickerItem(OBSERVER_PACKAGE),
                    useUnmergedTree = true,
                )
                .fetchSemanticsNodes()
                .isNotEmpty()
        }
        composeRule.onNodeWithTag(
            TunnelHomeTags.editorAppPickerItem(OBSERVER_PACKAGE),
            useUnmergedTree = true,
        ).performClick()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_APP_PICKER_DONE_BUTTON, useUnmergedTree = true)
            .performClick()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SAVE_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = EDITOR_TIMEOUT) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }
        screenshot(4, "xhttp_visibility_policy_saved")

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        screenshot(5, "xhttp_visibility_connect_requested")
        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )
        waitForTerminalPhase(CONNECT_TIMEOUT)
        val phaseText = semanticsText(TunnelHomeTags.STATUS_PHASE)
        val detailText = semanticsText(TunnelHomeTags.STATUS_DETAIL)
        assertEquals(
            "Expected XHTTP visibility profile to connect successfully. phase='$phaseText' detail='$detailText'",
            TunnelPhase.Connected.name,
            phaseText,
        )
        waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)
        waitForDetailContains("Excluded apps=$OBSERVER_PACKAGE", CONNECT_TIMEOUT)
        screenshot(6, "xhttp_visibility_tunnel_connected")

        val routedAfterConnect = observeHost(ROUTED_HOST)
        screenshot(7, "observer_routed_under_tunnel")

        val bypassAfterConnect = observeHost(BYPASS_HOST)
        screenshot(8, "observer_bypass_under_tunnel")

        assertTrue(
            "Expected observer visibility snapshot to remain populated after connect for routed host.",
            routedAfterConnect.egress.isNotBlank(),
        )
        assertEquals(
            "Expected blacklisted observer app to stay on direct egress for routed host.",
            directRouted.egress,
            routedAfterConnect.egress,
        )
        assertFalse(
            "Expected blacklisted observer app to stay off the VPN default network for routed host. snapshot=$routedAfterConnect",
            routedAfterConnect.network.contains("active_iface=tun0"),
        )
        assertTrue(
            "Expected blacklisted observer app to keep reporting the VPN network presence via allNetworks for routed host. snapshot=$routedAfterConnect",
            routedAfterConnect.vpnTransportVisible,
        )
        assertTrue(
            "Expected blacklisted observer app to use wlan0 as its active interface for routed host. snapshot=$routedAfterConnect",
            routedAfterConnect.network.contains("active_iface=wlan0"),
        )
        assertTrue(
            "Expected blacklisted observer app to still see tun0 in visible networks for routed host. snapshot=$routedAfterConnect",
            routedAfterConnect.network.contains("tun0"),
        )
        assertEquals(
            "Expected bypass host $BYPASS_HOST to stay on direct egress after connect for the blacklisted observer app.",
            directBypass.egress,
            bypassAfterConnect.egress,
        )
        assertTrue(
            "Expected blacklisted observer app to keep reporting the VPN network presence via allNetworks for bypass host. snapshot=$bypassAfterConnect",
            bypassAfterConnect.vpnTransportVisible,
        )
        assertTrue(
            "Expected blacklisted observer app to use wlan0 as its active interface for bypass host. snapshot=$bypassAfterConnect",
            bypassAfterConnect.network.contains("active_iface=wlan0"),
        )

        runCatching {
            TunnelDeviceTestHarness.launchApp(
                device = device,
                packageName = packageName,
                launchTimeout = launchTimeout,
            )
            TunnelHomePage(device)
                .waitForReady(launchTimeout)
                .tapPrimary()
            Thread.sleep(2_000)
        }
        screenshot(9, "xhttp_visibility_tunnel_disconnected")
    }

    private fun observeHost(host: String): ObserverSnapshot {
        val extras = buildMap {
            put(OBSERVER_TARGET_HOST_EXTRA, host)
        }

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = OBSERVER_PACKAGE,
            launchTimeout = launchTimeout,
            freshProcess = true,
            stringExtras = extras,
        )

        val observerPage = ObserverPage(device).waitForReady(launchTimeout)
        observerPage.waitForResult(OBSERVER_TIMEOUT)
        observerPage.waitForNetworkSnapshot(OBSERVER_TIMEOUT)
        return ObserverSnapshot(
            host = host,
            egress = observerPage.resultText().trim(),
            vpnTransportVisible = observerPage.vpnTransportVisible(),
            network = observerPage.networkText().trim(),
        ).also { snapshot ->
            val message = "OBSERVER_VISIBILITY host=${snapshot.host} egress=${snapshot.egress} " +
                "vpnVisible=${snapshot.vpnTransportVisible} network=${snapshot.network}"
            Log.i(TAG, message)
            println(message)
        }
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

    private data class ObserverSnapshot(
        val host: String,
        val egress: String,
        val vpnTransportVisible: Boolean,
        val network: String,
    )

    private companion object {
        const val TAG = "TunnelObserverVisibility"
        const val OBSERVER_PACKAGE = "works.relux.vless_tun_observer"
        const val OBSERVER_TARGET_HOST_EXTRA = "observer_target_host"
        const val ROUTED_HOST = "api.ipify.org"
        const val BYPASS_HOST = "api64.ipify.org"
        const val OBSERVER_TIMEOUT = 45_000L
        const val EDITOR_TIMEOUT = 5_000L
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
    }
}
