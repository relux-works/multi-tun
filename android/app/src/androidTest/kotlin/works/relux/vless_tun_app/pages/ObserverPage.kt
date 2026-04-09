package works.relux.vless_tun_app.pages

import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until

class ObserverPage(
    private val device: UiDevice,
) {
    fun waitForReady(timeout: Long): ObserverPage {
        val found = device.wait(Until.hasObject(By.res(TITLE_TAG)), timeout) ||
            device.wait(Until.hasObject(By.text("Tunnel Observer")), timeout)
        check(found) {
            "Observer app did not become ready within ${timeout}ms."
        }
        return this
    }

    fun tapRefresh(): ObserverPage {
        val button = device.findObject(By.res(REFRESH_BUTTON_TAG))
            ?: device.findObject(By.text("Refresh Observer Egress"))
            ?: device.findObject(By.text("Checking..."))
        checkNotNull(button) { "Observer refresh button not found." }
        button.click()
        device.waitForIdle()
        return this
    }

    fun waitForResult(timeout: Long): ObserverPage {
        val deadline = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < deadline) {
            val error = errorText().trim()
            if (error.isNotBlank()) {
                throw AssertionError("Observer probe failed: $error")
            }
            val result = resultText().trim()
            if (hasCapturedObservation(result)) {
                return this
            }
            Thread.sleep(200)
        }
        throw AssertionError(
            "Expected observer egress result within ${timeout}ms. " +
                "Current value='${resultText().trim()}'. Error='${errorText().trim()}'.",
        )
    }

    fun resultText(): String {
        return device.findObject(By.res(RESULT_TAG))?.text
            ?: device.findObject(By.textContains("·"))?.text
            ?: ""
    }

    private fun errorText(): String {
        return device.findObject(By.res(ERROR_TAG))?.text.orEmpty()
    }

    private fun hasCapturedObservation(text: String): Boolean {
        if (text.isBlank() || text.equals("Not captured yet", ignoreCase = true)) {
            return false
        }
        return IP_LIKE_REGEX.containsMatchIn(text)
    }

    private companion object {
        const val TITLE_TAG = "Observer_Home_Title_text"
        const val REFRESH_BUTTON_TAG = "Observer_Home_Refresh_button"
        const val RESULT_TAG = "Observer_Home_Result_text"
        const val ERROR_TAG = "Observer_Home_Error_text"
        val IP_LIKE_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{2,}""")
    }
}
