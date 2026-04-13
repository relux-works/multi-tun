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
import works.relux.vless_tun_app.core.model.routingPolicy
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
        val routingPolicy = EffectiveRoutingPolicy.fromProfile(profile)
        val root = buildJsonObject {
            put("log", buildJsonObject {
                put("level", "debug")
            })
            put("dns", buildDnsConfig(routingPolicy))
            put("inbounds", buildJsonArray {
                add(buildTunInbound())
            })
            put("outbounds", buildJsonArray {
                add(buildProxyOutbound(profile))
                add(buildDirectOutbound(routingPolicy))
                add(buildJsonObject {
                    put("type", "block")
                    put("tag", "block")
                })
            })
            put("route", buildRouteConfig(routingPolicy))
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

    private fun buildDnsConfig(policy: EffectiveRoutingPolicy): JsonObject = buildJsonObject {
        put("servers", buildJsonArray {
            if (policy.needsDirectDns) {
                add(buildJsonObject {
                    put("type", "local")
                    put("tag", "dns-direct")
                    put("detour", "direct")
                })
            }
            add(buildTlsDnsServer(tag = "dns-bootstrap", detour = "direct"))
            add(buildTlsDnsServer(tag = "dns-proxy", detour = "proxy"))
        })
        put("rules", buildJsonArray {
            if (policy.bypassMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("rule_set", buildJsonArray {
                        add(JsonPrimitive("routing-bypass"))
                    })
                    put("action", "route")
                    put("server", "dns-direct")
                })
            }
            if (policy.routeMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("rule_set", buildJsonArray {
                        add(JsonPrimitive("routing-proxy"))
                    })
                    put("action", "route")
                    put("server", "dns-proxy")
                })
            }
        })
        put("final", if (policy.usesRouteAllowList) "dns-direct" else "dns-proxy")
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

    private fun buildDirectOutbound(policy: EffectiveRoutingPolicy): JsonObject = buildJsonObject {
        put("type", "direct")
        put("tag", "direct")
        put("domain_resolver", if (policy.needsDirectDns) "dns-direct" else "dns-bootstrap")
    }

    private fun buildRouteConfig(policy: EffectiveRoutingPolicy): JsonObject = buildJsonObject {
        put("auto_detect_interface", true)
        put("default_domain_resolver", buildJsonObject {
            put("server", if (policy.usesRouteAllowList) "dns-direct" else "dns-bootstrap")
            put("strategy", "prefer_ipv4")
        })
        put("rule_set", buildJsonArray {
            if (policy.bypassMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("type", "inline")
                    put("tag", "routing-bypass")
                    put("rules", buildJsonArray {
                        add(buildJsonObject {
                            put("domain_suffix", policy.renderableBypassMasks())
                        })
                    })
                })
            }
            if (policy.routeMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("type", "inline")
                    put("tag", "routing-proxy")
                    put("rules", buildJsonArray {
                        add(buildJsonObject {
                            put("domain_suffix", policy.renderableRouteMasks())
                        })
                    })
                })
            }
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
            if (policy.bypassMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("rule_set", buildJsonArray {
                        add(JsonPrimitive("routing-bypass"))
                    })
                    put("action", "route")
                    put("outbound", "direct")
                })
            }
            if (policy.routeMasks.isNotEmpty()) {
                add(buildJsonObject {
                    put("rule_set", buildJsonArray {
                        add(JsonPrimitive("routing-proxy"))
                    })
                    put("action", "route")
                    put("outbound", "proxy")
                })
            }
        })
        put("final", if (policy.usesRouteAllowList) "direct" else "proxy")
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

private data class EffectiveRoutingPolicy(
    val routeMasks: List<String>,
    val bypassMasks: List<String>,
) {
    val usesRouteAllowList: Boolean
        get() = routeMasks.isNotEmpty()

    val needsDirectDns: Boolean
        get() = usesRouteAllowList || bypassMasks.isNotEmpty()

    fun renderableRouteMasks(): JsonArray = buildJsonArray {
        routeMasks.forEach { add(JsonPrimitive(it.trimStart('.'))) }
    }

    fun renderableBypassMasks(): JsonArray = buildJsonArray {
        bypassMasks.forEach { add(JsonPrimitive(it.trimStart('.'))) }
    }

    companion object {
        fun fromProfile(profile: TunnelProfile): EffectiveRoutingPolicy {
            val routingPolicy = profile.routingPolicy()
            return EffectiveRoutingPolicy(
                routeMasks = routingPolicy.routeMasks,
                bypassMasks = routingPolicy.bypassMasks,
            )
        }
    }
}
