package works.relux.vless_tun_app

import android.app.Application
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

class VlessTunApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        initializeLibbox()
    }

    private fun initializeLibbox() {
        if (!isLibboxInitialized.compareAndSet(false, true)) {
            return
        }

        val baseDir = filesDir.apply { mkdirs() }
        val workingDir = (getExternalFilesDir(null) ?: baseDir).apply { mkdirs() }
        val tempDir = cacheDir.apply { mkdirs() }

        val preferredLocale = Locale.getDefault().toLanguageTag().replace("-", "_")
        runCatching {
            Libbox.setLocale(preferredLocale)
        }.recoverCatching {
            Libbox.setLocale("en_US")
        }.getOrElse {
            // Locale negotiation is non-critical for tunnel bring-up.
        }
        Libbox.setup(
            SetupOptions().apply {
                setBasePath(baseDir.absolutePath)
                setWorkingPath(workingDir.absolutePath)
                setTempPath(tempDir.absolutePath)
                setFixAndroidStack(false)
                setLogMaxLines(3000)
                setDebug(false)
                setCrashReportSource("VlessTunApplication")
            },
        )
    }

    private companion object {
        val isLibboxInitialized = AtomicBoolean(false)
    }
}
