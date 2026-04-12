package works.relux.vless_tun_app.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import works.relux.vless_tun_app.core.persistence.CrashLogEntry
import works.relux.vless_tun_app.core.persistence.CrashLogWrite

class AppDiagnosticsTest {
    @Test
    fun uncaughtExceptionHandlerPersistsReportBeforeDelegating() {
        val persisted = mutableListOf<CrashLogWrite>()
        var delegatedThread: Thread? = null
        var delegatedThrowable: Throwable? = null
        val previousHandler = Thread.UncaughtExceptionHandler { thread, throwable ->
            delegatedThread = thread
            delegatedThrowable = throwable
        }
        val handler = AppCrashLoggingUncaughtExceptionHandler(
            persistReport = persisted::add,
            installedAppInfo = InstalledAppInfo(
                packageName = "works.relux.android.vlesstun.app",
                versionName = "1.0.5",
                versionCode = 5,
                targetSdk = 35,
                minSdk = 33,
            ),
            previousHandler = previousHandler,
            deviceSnapshot = DeviceSnapshot(
                manufacturer = "Samsung",
                model = "Galaxy",
                androidRelease = "15",
                sdkInt = 35,
            ),
            clock = { 1234L },
        )
        val thread = Thread.currentThread()
        val throwable = IllegalStateException("boom")

        handler.uncaughtException(thread, throwable)

        assertEquals(1, persisted.size)
        assertEquals(1234L, persisted.single().handledAtEpochMillis)
        assertEquals(thread.name, persisted.single().threadName)
        assertEquals("java.lang.IllegalStateException", persisted.single().exceptionClass)
        assertEquals("boom", persisted.single().exceptionMessage)
        assertEquals(thread, delegatedThread)
        assertEquals(throwable, delegatedThrowable)
        assertTrue(persisted.single().stackTrace.contains("IllegalStateException"))
    }

    @Test
    fun formatCrashLogEntryIncludesCoreMetadata() {
        val text = formatCrashLogEntry(
            CrashLogEntry(
                id = 42,
                handledAtEpochMillis = 1_700_000_000_000,
                threadName = "main",
                exceptionClass = "java.lang.IllegalStateException",
                exceptionMessage = "boom",
                stackTrace = "java.lang.IllegalStateException: boom\n\tat example.Main.main(Main.kt:1)",
                packageName = "works.relux.android.vlesstun.app",
                appVersionName = "1.0.5",
                appVersionCode = 5,
                deviceManufacturer = "Samsung",
                deviceModel = "Galaxy",
                androidRelease = "15",
                sdkInt = 35,
            ),
        )

        assertTrue(text.contains("Handled at:"))
        assertTrue(text.contains("Exception: java.lang.IllegalStateException"))
        assertTrue(text.contains("Message: boom"))
        assertTrue(text.contains("Thread: main"))
        assertTrue(text.contains("App: works.relux.android.vlesstun.app 1.0.5 (5)"))
        assertTrue(text.contains("Device: Samsung Galaxy"))
        assertTrue(text.contains("Android: 15 (SDK 35)"))
        assertTrue(text.contains("Main.kt:1"))
    }
}
