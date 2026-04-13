package works.relux.vless_tun_app.platform.xray

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RealXrayRuntimeTest {
    @Test
    fun prepareRuntimePaths_disablesMphCacheUntilItIsExplicitlyBuilt() {
        val filesDir = createTempDirectory(prefix = "xray-runtime-paths-").toFile()

        try {
            val runtimePaths = prepareRuntimePaths(filesDir)

            assertTrue(runtimePaths.dataDir.isDirectory)
            assertEquals(File(filesDir, "xray/data"), runtimePaths.dataDir)
            assertEquals("", runtimePaths.mphCachePath)
            assertFalse(File(filesDir, "xray/cache/matcher.cache").exists())
        } finally {
            filesDir.deleteRecursively()
        }
    }
}
