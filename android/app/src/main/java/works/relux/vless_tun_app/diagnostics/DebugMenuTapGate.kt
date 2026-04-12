package works.relux.vless_tun_app.diagnostics

class DebugMenuTapGate(
    private val requiredTapCount: Int = 7,
) {
    private var tapCount = 0

    fun registerTap(): Boolean {
        tapCount += 1
        if (tapCount < requiredTapCount) {
            return false
        }
        tapCount = 0
        return true
    }

    fun reset() {
        tapCount = 0
    }
}
