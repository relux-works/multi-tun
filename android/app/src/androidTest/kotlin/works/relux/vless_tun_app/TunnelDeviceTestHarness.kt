package works.relux.vless_tun_app

import android.content.Intent
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.io.File
import java.util.Base64
import works.relux.vless_tun_app.core.model.DefaultTunnelCatalog
import works.relux.vless_tun_app.core.model.TunnelSourceMode
import works.relux.vless_tun_app.core.persistence.TunnelCatalog
import works.relux.vless_tun_app.core.persistence.TunnelCatalogStore

internal object TunnelDeviceTestHarness {
    const val SOURCE_URL_ARG = "vless_source_url"
    const val SOURCE_URL_B64_ARG = "vless_source_url_b64"
    const val OBSERVER_BOOTSTRAP_IP_ARG = "observer_bootstrap_ip"

    fun requiredSourceUrl(): String {
        val sourceUrl = InstrumentationRegistry.getArguments().getString(SOURCE_URL_ARG).orEmpty().trim()
        val sourceUrlBase64 = InstrumentationRegistry.getArguments().getString(SOURCE_URL_B64_ARG).orEmpty().trim()
        val decodedSourceUrl = if (sourceUrlBase64.isNotBlank()) {
            runCatching {
                Base64.getDecoder().decode(sourceUrlBase64).toString(Charsets.UTF_8).trim()
            }.getOrElse { error ->
                throw IllegalStateException("Failed to decode instrumentation arg '$SOURCE_URL_B64_ARG': ${error.message}", error)
            }
        } else {
            ""
        }
        val resolvedSourceUrl = decodedSourceUrl.ifBlank { sourceUrl }
        check(resolvedSourceUrl.isNotBlank()) {
            "Missing instrumentation arg '$SOURCE_URL_ARG' or '$SOURCE_URL_B64_ARG'. " +
                "Pass -e $SOURCE_URL_ARG <url> or -e $SOURCE_URL_B64_ARG <base64>."
        }
        return resolvedSourceUrl
    }

    fun observerBootstrapIp(): String {
        val bootstrapIp = InstrumentationRegistry.getArguments().getString(OBSERVER_BOOTSTRAP_IP_ARG).orEmpty().trim()
        check(bootstrapIp.isNotBlank()) {
            "Missing instrumentation arg '$OBSERVER_BOOTSTRAP_IP_ARG'. Pass -e $OBSERVER_BOOTSTRAP_IP_ARG <ipv4>."
        }
        return bootstrapIp
    }

    fun sourceUrlOrDefault(default: String): String {
        return runCatching { requiredSourceUrl() }.getOrDefault(default)
    }

    fun seedCatalog(sourceUrl: String) {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val catalogStore = TunnelCatalogStore(
            storageFile = File(targetContext.filesDir, "config/tunnel-catalog.json"),
        )
        val seededProfile = DefaultTunnelCatalog.defaultProfile.copy(
            sourceMode = TunnelSourceMode.ProxyResolver,
            sourceUrl = sourceUrl,
            host = "",
            serverName = "",
            uuid = "",
        )
        catalogStore.save(
            TunnelCatalog(
                profiles = listOf(seededProfile),
                selectedProfileId = seededProfile.id,
            ),
        )
    }

    fun launchApp(
        device: UiDevice,
        packageName: String,
        launchTimeout: Long,
        freshProcess: Boolean = false,
        stringExtras: Map<String, String> = emptyMap(),
    ) {
        device.pressHome()
        device.waitForIdle()

        if (freshProcess) {
            val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
            if (packageName != targetContext.packageName) {
                device.executeShellCommand("am force-stop $packageName")
                Thread.sleep(500)
            }
        }

        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val launchIntent = targetContext.packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        val explicitComponent = launchIntent?.component?.flattenToString()
            ?: resolveLauncherComponent(device, packageName)

        if (explicitComponent != null) {
            val extras = stringExtras.entries.joinToString(" ") { (key, value) ->
                "--es $key $value"
            }
            val command = buildString {
                append("am start -W -n ")
                append(explicitComponent)
                if (extras.isNotBlank()) {
                    append(' ')
                    append(extras)
                }
            }
            device.executeShellCommand(command)
        } else {
            device.executeShellCommand("monkey -p $packageName -c android.intent.category.LAUNCHER 1")
        }

        val appVisible = device.wait(Until.hasObject(By.pkg(packageName).depth(0)), launchTimeout) ||
            device.wait(Until.hasObject(By.text("Tunnel Home")), launchTimeout) ||
            device.wait(Until.hasObject(By.text("Tunnel Observer")), launchTimeout)
        check(appVisible) {
            "App package $packageName did not become visible after shell launch."
        }
    }

    private fun resolveLauncherComponent(
        device: UiDevice,
        packageName: String,
    ): String? {
        val result = device.executeShellCommand("cmd package resolve-activity --brief $packageName")
            .lineSequence()
            .map(String::trim)
            .filter(String::isNotBlank)
            .lastOrNull()
            ?: return null
        return if (result.contains('/')) {
            result
        } else {
            null
        }
    }

    fun maybeApproveVpnConsent(
        device: UiDevice,
        timeout: Long,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < deadline) {
            maybeTrustApplication(device)
            val approvalButton = findApprovalButton(device)
            if (approvalButton != null) {
                approvalButton.click()
                device.waitForIdle()
                Thread.sleep(750)
                return true
            }
            Thread.sleep(250)
        }
        return false
    }

    private fun maybeTrustApplication(device: UiDevice) {
        val trustSelector = listOf(
            By.textContains("trust"),
            By.textContains("Trust"),
            By.textContains("remember"),
            By.textContains("Remember"),
        )
        trustSelector.firstNotNullOfOrNull(device::findObject)?.click()
    }

    private fun findApprovalButton(device: UiDevice): UiObject2? {
        val selectors = listOf(
            By.res("android", "button1"),
            By.res("miuix.appcompat", "button1"),
            By.text("OK"),
            By.text("Allow"),
            By.text("Continue"),
            By.text("Connect"),
            By.text("Yes"),
            By.text("ok"),
            By.text("allow"),
            By.text("continue"),
            By.text("connect"),
            By.desc("OK"),
            By.desc("Allow"),
            By.desc("Continue"),
            By.desc("Connect"),
            By.desc("Yes"),
        )
        return selectors.firstNotNullOfOrNull(device::findObject)
    }
}
