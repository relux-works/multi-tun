package works.relux.vless_tun_app.pages

import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import com.uitesttools.uitest.pageobject.PageElement
import works.relux.vless_tun_app.core.runtime.TunnelPhase
import works.relux.vless_tun_app.feature.tunnel.TunnelHomeTags

class TunnelHomePage(
    override val device: UiDevice,
) : PageElement {
    override val readyMarker = TunnelHomeTags.TITLE

    override fun waitForReady(timeout: Long): TunnelHomePage {
        val found = device.wait(Until.hasObject(By.res(TunnelHomeTags.TITLE)), timeout) ||
            device.wait(Until.hasObject(By.text("Tunnel Home")), timeout) ||
            device.wait(Until.hasObject(By.textContains("Tunnel")), timeout)

        if (!found) {
            throw AssertionError(
                "Page '${this::class.simpleName}' did not become ready within ${timeout}ms. " +
                    "Expected title by tag '${TunnelHomeTags.TITLE}' or visible text 'Tunnel Home'.",
            )
        }
        return this
    }

    val title: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.TITLE))
            ?: device.findObject(By.text("Tunnel Home"))
            ?: device.findObject(By.textContains("Tunnel"))

    val primaryButton: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.PRIMARY_BUTTON))
            ?: device.findObject(By.text("Connect"))
            ?: device.findObject(By.text("Disconnect"))

    val egressRefreshButton: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.EGRESS_REFRESH_BUTTON))
            ?: device.findObject(By.text("Check Egress"))
            ?: device.findObject(By.text("Checking..."))

    val directEgress: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.EGRESS_DIRECT_VALUE))

    val tunneledEgress: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.EGRESS_TUNNEL_VALUE))

    val egressError: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.EGRESS_ERROR_VALUE))

    val phase: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.STATUS_PHASE))
            ?: device.findObject(By.text(TunnelPhase.Connected.name))
            ?: device.findObject(By.text(TunnelPhase.Disconnected.name))

    val detail: UiObject2?
        get() = device.findObject(By.res(TunnelHomeTags.STATUS_DETAIL))

    fun tapPrimary(): TunnelHomePage {
        primaryButton?.click()
        device.waitForIdle()
        return this
    }

    fun tapRefreshEgress(): TunnelHomePage {
        egressRefreshButton?.click()
        device.waitForIdle()
        return this
    }

    fun waitForPhase(expected: TunnelPhase, timeout: Long): TunnelHomePage {
        val found = device.wait(Until.hasObject(By.text(expected.name)), timeout) ||
            waitForStatusPhaseText(expected.name, timeout)

        if (!found) {
            throw AssertionError("Expected tunnel phase '${expected.name}' within ${timeout}ms.")
        }
        return this
    }

    fun waitForDirectEgress(timeout: Long): TunnelHomePage {
        waitForEgressObservation(
            label = "Direct egress",
            selector = { directEgress?.text.orEmpty() },
            timeout = timeout,
        )
        return this
    }

    fun waitForTunneledEgress(timeout: Long): TunnelHomePage {
        revealLowerEgressContent()
        waitForEgressObservation(
            label = "Tunnel egress",
            selector = { tunneledEgress?.text.orEmpty() },
            timeout = timeout,
        )
        return this
    }

    fun directEgressText(): String = directEgress?.text.orEmpty()

    fun tunneledEgressText(): String = tunneledEgress?.text.orEmpty()

    fun egressErrorText(): String = egressError?.text.orEmpty()

    fun waitForDetailContains(text: String, timeout: Long): TunnelHomePage {
        val found = waitForStatusDetailText(text, timeout) ||
            device.wait(Until.hasObject(By.textContains(text)), timeout)
        if (!found) {
            throw AssertionError("Expected tunnel detail containing '$text' within ${timeout}ms.")
        }
        return this
    }

    private fun waitForStatusPhaseText(expected: String, timeout: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < deadline) {
            val text = phase?.text
            if (text == expected) {
                return true
            }
            Thread.sleep(200)
        }
        return false
    }

    private fun waitForStatusDetailText(expected: String, timeout: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < deadline) {
            val text = detail?.text.orEmpty()
            if (text.contains(expected, ignoreCase = true)) {
                return true
            }
            Thread.sleep(200)
        }
        return false
    }

    private fun waitForEgressObservation(
        label: String,
        selector: () -> String,
        timeout: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeout
        var attempts = 0
        while (System.currentTimeMillis() < deadline) {
            if (label == "Tunnel egress" && attempts % 5 == 0) {
                revealLowerEgressContent()
            }
            val text = selector().trim()
            val errorText = egressErrorText().trim()
            if (errorText.isNotBlank()) {
                throw AssertionError("Egress check failed while waiting for '$label': $errorText")
            }
            if (hasCapturedObservation(text, label)) {
                return
            }
            attempts += 1
            Thread.sleep(200)
        }
        throw AssertionError(
            "Expected $label observation within ${timeout}ms. " +
                "Current value='${selector().trim()}'. Error='${egressErrorText().trim()}'.",
        )
    }

    private fun revealLowerEgressContent() {
        val centerX = device.displayWidth / 2
        val startY = (device.displayHeight * 0.82f).toInt()
        val endY = (device.displayHeight * 0.42f).toInt()
        device.swipe(centerX, startY, centerX, endY, 20)
        device.waitForIdle()
    }

    private fun hasCapturedObservation(
        text: String,
        label: String,
    ): Boolean {
        if (text.isBlank()) {
            return false
        }
        if (!text.startsWith("$label:")) {
            return false
        }
        val value = text.substringAfter(':', "").trim()
        if (value.isBlank() || value.equals("Not captured yet", ignoreCase = true)) {
            return false
        }
        return IP_LIKE_REGEX.containsMatchIn(value)
    }

    private companion object {
        val IP_LIKE_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{2,}""")
    }
}
