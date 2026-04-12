package works.relux.vless_tun_app.diagnostics

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DebugMenuDismissGateTest {
    @Test
    fun blocksDismissDuringInitialGuardWindow() {
        var now = 1_000L
        val gate = DebugMenuDismissGate(dismissGuardMillis = 1_000, clock = { now })

        gate.markOpened()
        assertFalse(gate.canDismiss())

        now = 1_999L
        assertFalse(gate.canDismiss())

        now = 2_000L
        assertTrue(gate.canDismiss())
    }

    @Test
    fun resetRemovesGuardState() {
        var now = 1_000L
        val gate = DebugMenuDismissGate(dismissGuardMillis = 1_000, clock = { now })

        gate.markOpened()
        gate.reset()

        now = 1_001L
        assertTrue(gate.canDismiss())
    }
}
