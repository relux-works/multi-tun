package works.relux.vless_tun_app.platform.xray

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import works.relux.vless_tun_app.core.model.excludePackages
import works.relux.vless_tun_app.core.model.includePackages
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.model.TunnelRoutingPolicy
import works.relux.vless_tun_app.core.model.routingPolicy
import works.relux.vless_tun_app.core.render.RenderedTunnelConfig
import works.relux.vless_tun_app.core.runtime.TunnelAddress
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeBackend
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeManifest
import works.relux.vless_tun_app.core.runtime.TunnelRoute

class XrayTunnelConfigRenderer {
    fun render(profile: TunnelProfile): RenderedTunnelConfig {
        val share = parseShare(profile.sourceUrl.trim())
        val policy = profile.routingPolicy()
        val root = buildJsonObject {
            put("inbounds", buildJsonArray {
                add(buildTunInbound())
            })
            put("outbounds", buildJsonArray {
                add(buildProxyOutbound(share))
                add(buildFreedomOutbound())
                add(buildBlackholeOutbound())
            })
            put("routing", buildRoutingConfig(policy))
        }

        return RenderedTunnelConfig(
            profileId = profile.id,
            profileName = profile.name,
            json = JSON.encodeToString(JsonElement.serializer(), root),
            runtimeManifest = buildRuntimeManifest(profile),
            backend = TunnelRuntimeBackend.Xray,
        )
    }

    private fun buildTunInbound() = buildJsonObject {
        put("tag", "tun-in")
        put("port", 0)
        put("protocol", "tun")
        put("settings", buildJsonObject {
            put("name", "android-tun")
            put("MTU", DEFAULT_MTU)
            put("userLevel", 0)
        })
        put("sniffing", buildJsonObject {
            put("enabled", true)
            put("routeOnly", true)
            put("destOverride", buildJsonArray {
                add(JsonPrimitive("http"))
                add(JsonPrimitive("tls"))
                add(JsonPrimitive("quic"))
            })
        })
    }

    private fun buildProxyOutbound(share: XrayVlessShare) = buildJsonObject {
        put("protocol", "vless")
        put("tag", "proxy")
        put("settings", buildJsonObject {
            put("address", share.address)
            put("port", share.port)
            put("level", 0)
            put("email", "")
            put("id", share.uuid)
            put("flow", share.flow)
            put("seed", "")
            put("encryption", share.encryption)
            put("testpre", 0)
        })
        put("streamSettings", buildJsonObject {
            put("network", "xhttp")
            put("security", share.security)
            put("realitySettings", buildJsonObject {
                put("show", false)
                put("fingerprint", share.fingerprint)
                put("serverName", share.serverName)
                put("password", share.publicKey)
                put("publicKey", share.publicKey)
                put("shortId", share.shortId)
                put("spiderX", share.spiderX)
            })
            put("xhttpSettings", buildJsonObject {
                put("host", share.requestHost)
                put("path", share.path)
                put("mode", share.mode)
                put("xPaddingBytes", "0")
                put("xPaddingObfsMode", false)
                put("xPaddingKey", "")
                put("xPaddingHeader", "")
                put("xPaddingPlacement", "")
                put("xPaddingMethod", "")
                put("uplinkHTTPMethod", "")
                put("sessionPlacement", "")
                put("sessionKey", "")
                put("seqPlacement", "")
                put("seqKey", "")
                put("uplinkDataPlacement", "")
                put("uplinkDataKey", "")
                put("uplinkChunkSize", "0")
                put("noGRPCHeader", false)
                put("noSSEHeader", false)
                put("scMaxEachPostBytes", "0")
                put("scMinPostsIntervalMs", "0")
                put("scMaxBufferedPosts", 0)
                put("scStreamUpServerSecs", "0")
                put("serverMaxHeaderBytes", 0)
                put("xmux", buildJsonObject {
                    put("maxConcurrency", "0")
                    put("maxConnections", "0")
                    put("cMaxReuseTimes", "0")
                    put("hMaxRequestTimes", "0")
                    put("hMaxReusableSecs", "0")
                    put("hKeepAlivePeriod", 0)
                })
            })
        })
        put("targetStrategy", "")
    }

    private fun buildFreedomOutbound() = buildJsonObject {
        put("tag", "direct")
        put("protocol", "freedom")
        put("settings", buildJsonObject {})
    }

    private fun buildBlackholeOutbound() = buildJsonObject {
        put("tag", "block")
        put("protocol", "blackhole")
        put("settings", buildJsonObject {})
    }

    private fun buildRoutingConfig(policy: TunnelRoutingPolicy) = buildJsonObject {
        val bypassDomains = policy.bypassMasks.renderXrayDomains()
        val routedDomains = policy.routeMasks.renderXrayDomains()
        val defaultTag = if (policy.usesRouteAllowList) "direct" else "proxy"
        put("domainStrategy", "AsIs")
        put("rules", buildJsonArray {
            add(buildJsonObject {
                put("type", "field")
                put("inboundTag", buildJsonArray { add(JsonPrimitive("tun-in")) })
                put("ip", buildJsonArray {
                    PRIVATE_IP_RULES.forEach { cidr ->
                        add(JsonPrimitive(cidr))
                    }
                })
                put("outboundTag", "direct")
            })
            if (bypassDomains.isNotEmpty()) {
                add(buildJsonObject {
                    put("type", "field")
                    put("inboundTag", buildJsonArray { add(JsonPrimitive("tun-in")) })
                    put("domain", JsonArray(bypassDomains.map(::JsonPrimitive)))
                    put("outboundTag", "direct")
                })
            }
            if (routedDomains.isNotEmpty()) {
                add(buildJsonObject {
                    put("type", "field")
                    put("inboundTag", buildJsonArray { add(JsonPrimitive("tun-in")) })
                    put("domain", JsonArray(routedDomains.map(::JsonPrimitive)))
                    put("outboundTag", "proxy")
                })
            }
            add(buildJsonObject {
                put("type", "field")
                put("inboundTag", buildJsonArray { add(JsonPrimitive("tun-in")) })
                put("outboundTag", defaultTag)
            })
        })
    }

    private fun buildRuntimeManifest(profile: TunnelProfile): TunnelRuntimeManifest {
        return TunnelRuntimeManifest(
            sessionName = "vless-tun:${profile.name}",
            mtu = DEFAULT_MTU,
            addresses = listOf(
                TunnelAddress(address = "172.19.0.1", prefixLength = 30),
                TunnelAddress(address = "fdfe:dcba:9876::1", prefixLength = 126),
            ),
            routes = listOf(
                TunnelRoute(address = "0.0.0.0", prefixLength = 0),
                TunnelRoute(address = "::", prefixLength = 0),
            ),
            dnsServers = listOf(
                "1.1.1.1",
                "2606:4700:4700::1111",
            ),
            includePackages = profile.includePackages(),
            excludePackages = profile.excludePackages(),
            allowBypass = true,
            isMockDataPlane = false,
        )
    }

    private fun parseShare(rawUri: String): XrayVlessShare {
        require(rawUri.startsWith("vless://", ignoreCase = true)) {
            "Xray backend expects one inline VLESS URI."
        }

        val parsed = URI(rawUri)
        val query = decodeQuery(parsed.rawQuery)
        val network = query["type"] ?: query["network"] ?: "tcp"
        require(network.equals("xhttp", ignoreCase = true)) {
            "Xray backend expects VLESS transport 'xhttp', got '$network'."
        }

        val security = query["security"].orEmpty()
        require(security.equals("reality", ignoreCase = true)) {
            "Xray backend expects VLESS security 'reality', got '$security'."
        }

        val address = parsed.host ?: error("Missing host in VLESS URI.")
        val uuid = parsed.rawUserInfo?.decodeUriComponent()
            ?.takeIf(String::isNotBlank)
            ?: error("Missing UUID in VLESS URI.")

        return XrayVlessShare(
            address = address,
            port = parsed.port.takeIf { it != -1 } ?: 443,
            uuid = uuid,
            encryption = query["encryption"].orEmpty().ifBlank { "none" },
            flow = query["flow"].orEmpty(),
            security = "reality",
            fingerprint = query["fp"] ?: query["fingerprint"] ?: "",
            serverName = query["sni"] ?: query["serverName"] ?: address,
            publicKey = query["pbk"] ?: query["publicKey"] ?: error("Missing Reality public key in VLESS URI."),
            shortId = query["sid"] ?: query["shortId"] ?: "",
            spiderX = query["spx"] ?: query["spiderX"] ?: "",
            requestHost = query["host"].orEmpty().ifBlank { address },
            path = query["path"].orEmpty().ifBlank { "/" },
            mode = query["mode"].orEmpty().ifBlank { "auto" },
        )
    }

    private fun decodeQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        return rawQuery.split("&")
            .mapNotNull { chunk ->
                if (chunk.isBlank()) return@mapNotNull null
                val pair = chunk.split("=", limit = 2)
                val key = pair[0].decodeUriComponent()
                val value = pair.getOrElse(1) { "" }.decodeUriComponent()
                key to value
            }
            .toMap()
    }

    private fun String.decodeUriComponent(): String = URLDecoder.decode(this, StandardCharsets.UTF_8)

    private fun List<String>.renderXrayDomains(): List<String> {
        return map { mask ->
            "domain:${mask.trim().trimStart('.')}"
        }.distinct()
    }

    private data class XrayVlessShare(
        val address: String,
        val port: Int,
        val uuid: String,
        val encryption: String,
        val flow: String,
        val security: String,
        val fingerprint: String,
        val serverName: String,
        val publicKey: String,
        val shortId: String,
        val spiderX: String,
        val requestHost: String,
        val path: String,
        val mode: String,
    )

    private companion object {
        val JSON = Json {
            prettyPrint = false
        }

        const val DEFAULT_MTU = 1500

        val PRIVATE_IP_RULES = listOf(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        )
    }
}
