package works.relux.vless_tun_app.core.runtime

data class TunnelAddress(
    val address: String,
    val prefixLength: Int,
)

data class TunnelRoute(
    val address: String,
    val prefixLength: Int,
)

data class TunnelRuntimeManifest(
    val sessionName: String,
    val mtu: Int,
    val addresses: List<TunnelAddress>,
    val routes: List<TunnelRoute>,
    val dnsServers: List<String>,
    val allowBypass: Boolean,
    val isMockDataPlane: Boolean,
)
