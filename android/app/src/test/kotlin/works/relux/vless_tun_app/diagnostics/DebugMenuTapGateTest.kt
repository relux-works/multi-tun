package works.relux.vless_tun_app.diagnostics

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DebugMenuTapGateTest {
    @Test
    fun opensOnSeventhTapAndResets() {
        val gate = DebugMenuTapGate(requiredTapCount = 7)

        repeat(6) {
            assertFalse(gate.registerTap())
        }
        assertTrue(gate.registerTap())
        assertFalse(gate.registerTap())
    }

    @Test
    fun resetClearsProgress() {
        val gate = DebugMenuTapGate(requiredTapCount = 3)

        assertFalse(gate.registerTap())
        gate.reset()
        assertFalse(gate.registerTap())
        assertFalse(gate.registerTap())
        assertTrue(gate.registerTap())
    }
}
