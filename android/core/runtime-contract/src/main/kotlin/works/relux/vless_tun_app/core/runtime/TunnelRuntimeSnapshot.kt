package works.relux.vless_tun_app.core.runtime

enum class TunnelPhase {
    Disconnected,
    PermissionRequired,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

data class TunnelRuntimeSnapshot(
    val phase: TunnelPhase = TunnelPhase.Disconnected,
    val activeProfileName: String? = null,
    val detail: String = "Tap connect to start the stub tunnel.",
    val renderedConfigPreview: String? = null,
)
