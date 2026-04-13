package works.relux.vless_tun_app.platform.xray

import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import libXray.DialerController
import libXray.LibXray

internal object LibXrayBridge {
    private val json = Json {
        ignoreUnknownKeys = true
    }

    init {
        LibXray.touch()
    }

    fun convertShareLinksToXrayJson(shareText: String): JsonObject {
        val payload = decodeResponse(
            LibXray.convertShareLinksToXrayJson(encodeBase64Text(shareText)),
        )
        return payload["data"] as? JsonObject ?: error("libXray returned an empty Xray config.")
    }

    fun registerControllers(controller: DialerController) {
        LibXray.registerDialerController(controller)
        LibXray.registerListenerController(controller)
    }

    fun initDns(
        controller: DialerController,
        server: String,
    ) {
        LibXray.initDns(controller, server)
    }

    fun resetDns() {
        LibXray.resetDns()
    }

    fun setTunFd(fd: Int) {
        LibXray.setTunFd(fd)
    }

    fun runXrayFromJson(
        datDir: String,
        mphCachePath: String,
        configJson: String,
    ) {
        val request = buildJsonObject {
            put("datDir", datDir)
            put("mphCachePath", mphCachePath)
            put("configJSON", configJson)
        }
        decodeResponse(
            LibXray.runXrayFromJSON(encodeBase64Text(request.toString())),
        )
    }

    fun stopXray() {
        decodeResponse(LibXray.stopXray())
    }

    fun isRunning(): Boolean = LibXray.getXrayState()

    fun xrayVersion(): String {
        return decodeResponse(LibXray.xrayVersion())["data"]
            ?.jsonPrimitive
            ?.content
            .orEmpty()
    }

    private fun encodeBase64Text(value: String): String {
        return Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
    }

    private fun decodeResponse(raw: String): JsonObject {
        check(raw.isNotBlank()) {
            "libXray returned an empty response."
        }
        val decoded = Base64.getDecoder().decode(raw).toString(Charsets.UTF_8)
        val response = json.parseToJsonElement(decoded) as? JsonObject
            ?: error("libXray returned a non-object response.")
        check(response["success"]?.jsonPrimitive?.booleanOrNull == true) {
            response["error"]?.jsonPrimitive?.content?.takeIf(String::isNotBlank)
                ?: "libXray returned an unsuccessful response."
        }
        return response
    }
}
