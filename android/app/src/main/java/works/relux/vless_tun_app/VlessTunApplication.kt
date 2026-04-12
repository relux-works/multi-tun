package works.relux.vless_tun_app

import android.app.Application
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import works.relux.vless_tun_app.core.persistence.CrashLogStore
import works.relux.vless_tun_app.diagnostics.AppCrashLoggingUncaughtExceptionHandler
import works.relux.vless_tun_app.diagnostics.InstalledAppInfo

class VlessTunApplication : Application() {
    lateinit var crashLogStore: CrashLogStore
        private set

    override fun onCreate() {
        super.onCreate()
        crashLogStore = CrashLogStore(this).also(CrashLogStore::warmUp)
        installCrashHandler()
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

    private fun installCrashHandler() {
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler(
            AppCrashLoggingUncaughtExceptionHandler(
                persistReport = crashLogStore::record,
                installedAppInfo = InstalledAppInfo.from(this),
                previousHandler = previousHandler,
            ),
        )
    }

    private companion object {
        val isLibboxInitialized = AtomicBoolean(false)
    }
}
