package works.relux.vless_tun_app

import android.util.Log
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags

@RunWith(AndroidJUnit4::class)
class TunnelRoutingPolicySmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)

    @get:Rule
    val composeRule = createEmptyComposeRule()

    @Before
    fun setUp() {
        TunnelDeviceTestHarness.seedCatalog(
            sourceUrl = TunnelDeviceTestHarness.requiredSourceUrl(),
        )
    }

    @Test
    fun routeMasksAndBypassMasksAffectRealTraffic() {
        val directRoutedIp = probeIpify(ROUTED_HOST)
        val directBypassIp = probeIpify(BYPASS_HOST)

        TunnelDeviceTestHarness.launchApp(
            device = device,
            packageName = PACKAGE_NAME,
            launchTimeout = LAUNCH_TIMEOUT,
            stringExtras = mapOf(
                UiTestLaunchContract.EXTRA_ACTION to UiTestLaunchContract.ACTION_OPEN_EDIT_SELECTED_EDITOR,
                UiTestLaunchContract.EXTRA_LAYOUT to UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP,
            ),
        )

        composeRule.onNodeWithTag(TunnelHomeTags.SCREEN, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
            .assertIsDisplayed()
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_ROUTE_MASKS_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement("ipify.org")
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_BYPASS_MASKS_INPUT, useUnmergedTree = true)
            .performScrollTo()
            .performTextReplacement("api64.ipify.org")
        composeRule.onNodeWithTag(TunnelHomeTags.EDITOR_SAVE_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule
                .onAllNodesWithTag(TunnelHomeTags.EDITOR_CARD, useUnmergedTree = true)
                .fetchSemanticsNodes()
                .isEmpty()
        }

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        TunnelDeviceTestHarness.maybeApproveVpnConsent(
            device = device,
            timeout = VPN_CONSENT_TIMEOUT,
        )
        waitForTerminalPhase(CONNECT_TIMEOUT)
        val phaseText = semanticsText(TunnelHomeTags.STATUS_PHASE)
        val detailText = semanticsText(TunnelHomeTags.STATUS_DETAIL)
        assertEquals(
            "Expected routed profile to connect successfully. phase='$phaseText' detail='$detailText'",
            TunnelPhase.Connected.name,
            phaseText,
        )
        waitForDetailContains("TUN interface established", CONNECT_TIMEOUT)

        val tunneledRoutedIp = probeIpify(ROUTED_HOST)
        val bypassAfterConnectIp = probeIpify(BYPASS_HOST)
        logProbe("direct_route", directRoutedIp)
        logProbe("direct_bypass", directBypassIp)
        logProbe("connected_route", tunneledRoutedIp)
        logProbe("connected_bypass", bypassAfterConnectIp)

        assertNotEquals(
            "Expected routed host $ROUTED_HOST to switch to tunnel egress after connect.",
            directRoutedIp,
            tunneledRoutedIp,
        )
        assertEquals(
            "Expected bypass host $BYPASS_HOST to stay on direct egress even while $ROUTED_HOST is routed.",
            directBypassIp,
            bypassAfterConnectIp,
        )
        assertNotEquals(
            "Expected bypass host $BYPASS_HOST to override the broader routed suffix ipify.org.",
            tunneledRoutedIp,
            bypassAfterConnectIp,
        )

        composeRule.onNodeWithTag(TunnelHomeTags.PRIMARY_BUTTON, useUnmergedTree = true)
            .performScrollTo()
            .performClick()
        composeRule.waitUntil(timeoutMillis = DISCONNECT_TIMEOUT) {
            semanticsText(TunnelHomeTags.STATUS_PHASE) == TunnelPhase.Disconnected.name
        }
    }

    private fun probeIpify(host: String): String {
        val client = OkHttpClient.Builder()
            .retryOnConnectionFailure(false)
            .build()
        repeat(3) { attempt ->
            runCatching {
                val request = Request.Builder()
                    .url("https://$host?format=text&ts=${System.currentTimeMillis()}")
                    .header("Cache-Control", "no-cache")
                    .build()
                client.newCall(request).execute().use { response ->
                    check(response.isSuccessful) { "HTTP ${response.code}" }
                    response.body?.string().orEmpty().trim()
                }.also { body ->
                    check(body.isNotBlank()) { "empty response body" }
                }
            }.onSuccess { return it }

            if (attempt < 2) {
                Thread.sleep(1_000)
            }
        }
        error("Failed to probe $host after retries.")
    }

    private fun logProbe(label: String, value: String) {
        val message = "ROUTING_PROBE_${label.uppercase()}=$value"
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
        const val PACKAGE_NAME = "works.relux.android.vlesstun.app"
        const val LAUNCH_TIMEOUT = 5_000L
        const val TAG = "TunnelRoutingPolicySmoke"
        const val ROUTED_HOST = "api.ipify.org"
        const val BYPASS_HOST = "api64.ipify.org"
        const val VPN_CONSENT_TIMEOUT = 10_000L
        const val CONNECT_TIMEOUT = 30_000L
        const val DISCONNECT_TIMEOUT = 10_000L
    }
}
