package works.relux.vless_tun_app.diagnostics

class DebugMenuDismissGate(
    private val dismissGuardMillis: Long = 1_000,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private var openedAtMillis: Long? = null

    fun markOpened() {
        openedAtMillis = clock()
    }

    fun canDismiss(): Boolean {
        val openedAt = openedAtMillis ?: return true
        return clock() - openedAt >= dismissGuardMillis
    }

    fun reset() {
        openedAtMillis = null
    }
}
