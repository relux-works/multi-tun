package works.relux.vless_tun_app.core.runtime

enum class TunnelRuntimeBackend {
    Singbox,
    Xray,
}

data class TunnelTunHandle(
    val fd: Int,
    val summary: String,
)
