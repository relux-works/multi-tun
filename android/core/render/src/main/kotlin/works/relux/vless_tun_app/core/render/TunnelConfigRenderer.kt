package works.relux.vless_tun_app.core.render

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.runtime.TunnelAddress
import works.relux.vless_tun_app.core.runtime.TunnelRoute
import works.relux.vless_tun_app.core.runtime.TunnelRuntimeManifest

data class RenderedTunnelConfig(
    val profileId: String,
    val profileName: String,
    val json: String,
    val runtimeManifest: TunnelRuntimeManifest,
)

class TunnelConfigRenderer {
    fun render(profile: TunnelProfile): RenderedTunnelConfig {
        val root = buildJsonObject {
            put("log", buildJsonObject {
                put("level", "debug")
            })
            put("dns", buildDnsConfig())
            put("inbounds", buildJsonArray {
                add(buildTunInbound())
            })
            put("outbounds", buildJsonArray {
                add(buildProxyOutbound(profile))
                add(buildDirectOutbound())
                add(buildJsonObject {
                    put("type", "block")
                    put("tag", "block")
                })
            })
            put("route", buildRouteConfig())
        }

        val runtimeManifest = TunnelRuntimeManifest(
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
            allowBypass = true,
            isMockDataPlane = false,
        )

        return RenderedTunnelConfig(
            profileId = profile.id,
            profileName = profile.name,
            json = JSON.encodeToString(JsonElement.serializer(), root),
            runtimeManifest = runtimeManifest,
        )
    }

    private fun buildDnsConfig(): JsonObject = buildJsonObject {
        put("servers", buildJsonArray {
            add(buildTlsDnsServer(tag = "dns-bootstrap", detour = "direct"))
            add(buildTlsDnsServer(tag = "dns-proxy", detour = "proxy"))
        })
        put("rules", buildJsonArray {
            add(buildJsonObject {
                put("action", "route")
                put("server", "dns-proxy")
            })
        })
        put("final", "dns-proxy")
        put("strategy", "prefer_ipv4")
        put("reverse_mapping", true)
    }

    private fun buildTunInbound(): JsonObject = buildJsonObject {
        put("type", "tun")
        put("tag", "tun-in")
        put("interface_name", "android-tun")
        put("address", buildJsonArray {
            add(JsonPrimitive("172.19.0.1/30"))
            add(JsonPrimitive("fdfe:dcba:9876::1/126"))
        })
        put("auto_route", true)
        put("strict_route", true)
        put("mtu", DEFAULT_MTU)
    }

    private fun buildProxyOutbound(profile: TunnelProfile): JsonObject = buildJsonObject {
        put("type", "vless")
        put("tag", "proxy")
        put("server", profile.host)
        put("server_port", profile.port)
        put("uuid", profile.uuid)
        put("domain_resolver", "dns-bootstrap")
        if (profile.flow.isNotBlank()) {
            put("flow", profile.flow)
        }
        buildTls(profile)?.let { put("tls", it) }
        buildTransport(profile)?.let { put("transport", it) }
    }

    private fun buildDirectOutbound(): JsonObject = buildJsonObject {
        put("type", "direct")
        put("tag", "direct")
        put("domain_resolver", "dns-bootstrap")
    }

    private fun buildRouteConfig(): JsonObject = buildJsonObject {
        put("auto_detect_interface", true)
        put("default_domain_resolver", buildJsonObject {
            put("server", "dns-bootstrap")
            put("strategy", "prefer_ipv4")
        })
        put("rules", buildJsonArray {
            add(buildJsonObject {
                put("protocol", "dns")
                put("action", "hijack-dns")
            })
            add(buildJsonObject {
                put("action", "sniff")
            })
            add(buildJsonObject {
                put("ip_is_private", true)
                put("action", "route")
                put("outbound", "direct")
            })
        })
        put("final", "proxy")
    }

    private fun buildTlsDnsServer(
        tag: String,
        detour: String,
    ): JsonObject = buildJsonObject {
        put("type", "tls")
        put("tag", tag)
        put("server", "1.1.1.1")
        put("server_port", 853)
        put("detour", detour)
        put("tls", buildJsonObject {
            put("enabled", true)
            put("server_name", "cloudflare-dns.com")
        })
    }

    private fun buildTransport(profile: TunnelProfile): JsonObject? {
        return when (profile.transport.lowercase()) {
            "", "tcp" -> null
            "grpc" -> buildJsonObject {
                put("type", "grpc")
                if (profile.serviceName.isNotBlank()) {
                    put("service_name", profile.serviceName)
                }
            }
            else -> buildJsonObject {
                put("type", profile.transport)
            }
        }
    }

    private fun buildTls(profile: TunnelProfile): JsonObject? {
        return when (profile.security.lowercase()) {
            "", "none" -> null
            "tls" -> buildJsonObject {
                put("enabled", true)
                if (profile.serverName.isNotBlank()) {
                    put("server_name", profile.serverName)
                }
                buildUtls(profile)?.let { put("utls", it) }
            }
            "reality" -> buildJsonObject {
                put("enabled", true)
                if (profile.serverName.isNotBlank()) {
                    put("server_name", profile.serverName)
                }
                buildUtls(profile)?.let { put("utls", it) }
                put("reality", buildJsonObject {
                    put("enabled", true)
                    put("public_key", profile.publicKey)
                    if (profile.shortId.isNotBlank()) {
                        put("short_id", profile.shortId)
                    }
                })
            }
            else -> buildJsonObject {
                put("enabled", true)
                if (profile.serverName.isNotBlank()) {
                    put("server_name", profile.serverName)
                }
            }
        }
    }

    private fun buildUtls(profile: TunnelProfile): JsonObject? {
        if (profile.fingerprint.isBlank()) {
            return null
        }
        return buildJsonObject {
            put("enabled", true)
            put("fingerprint", profile.fingerprint)
        }
    }

    private companion object {
        const val DEFAULT_MTU = 1400

        val JSON = Json {
            prettyPrint = true
        }
    }
}
