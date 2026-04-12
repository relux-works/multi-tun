package works.relux.vless_tun_app.diagnostics

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.util.Log
import androidx.core.content.pm.PackageInfoCompat
import java.io.PrintWriter
import java.io.StringWriter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.system.exitProcess
import works.relux.vless_tun_app.core.persistence.CrashLogEntry
import works.relux.vless_tun_app.core.persistence.CrashLogWrite

data class InstalledAppInfo(
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val targetSdk: Int,
    val minSdk: Int,
) {
    companion object {
        fun from(context: Context): InstalledAppInfo {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(0),
            )
            return InstalledAppInfo(
                packageName = context.packageName,
                versionName = packageInfo.versionName.orEmpty(),
                versionCode = PackageInfoCompat.getLongVersionCode(packageInfo),
                targetSdk = context.applicationInfo.targetSdkVersion,
                minSdk = context.applicationInfo.minSdkVersion,
            )
        }
    }
}

data class DeviceSnapshot(
    val manufacturer: String,
    val model: String,
    val androidRelease: String,
    val sdkInt: Int,
) {
    companion object {
        fun fromRuntime(): DeviceSnapshot {
            return DeviceSnapshot(
                manufacturer = Build.MANUFACTURER.orEmpty(),
                model = Build.MODEL.orEmpty(),
                androidRelease = Build.VERSION.RELEASE.orEmpty(),
                sdkInt = Build.VERSION.SDK_INT,
            )
        }
    }
}

data class DebugInfoRow(
    val label: String,
    val value: String,
)

data class AppDebugInfo(
    val rows: List<DebugInfoRow>,
)

class AppCrashLoggingUncaughtExceptionHandler(
    private val persistReport: (CrashLogWrite) -> Unit,
    private val installedAppInfo: InstalledAppInfo,
    private val previousHandler: Thread.UncaughtExceptionHandler?,
    private val deviceSnapshot: DeviceSnapshot = DeviceSnapshot.fromRuntime(),
    private val clock: () -> Long = System::currentTimeMillis,
) : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(thread: Thread, throwable: Throwable) {
        runCatching {
            persistReport(
                CrashLogWrite(
                    handledAtEpochMillis = clock(),
                    threadName = thread.name,
                    exceptionClass = throwable::class.java.name,
                    exceptionMessage = throwable.message.orEmpty(),
                    stackTrace = throwable.renderStackTrace(),
                    packageName = installedAppInfo.packageName,
                    appVersionName = installedAppInfo.versionName,
                    appVersionCode = installedAppInfo.versionCode,
                    deviceManufacturer = deviceSnapshot.manufacturer,
                    deviceModel = deviceSnapshot.model,
                    androidRelease = deviceSnapshot.androidRelease,
                    sdkInt = deviceSnapshot.sdkInt,
                ),
            )
        }.onFailure { error ->
            Log.e(TAG, "Failed to persist uncaught exception report.", error)
        }

        val delegated = previousHandler
        if (delegated != null && delegated !== this) {
            delegated.uncaughtException(thread, throwable)
            return
        }

        Process.killProcess(Process.myPid())
        exitProcess(10)
    }
}

fun buildAppDebugInfo(
    context: Context,
    crashDatabasePath: String,
    tunnelCatalogPath: String,
): AppDebugInfo {
    val installedAppInfo = InstalledAppInfo.from(context)
    val deviceSnapshot = DeviceSnapshot.fromRuntime()
    return AppDebugInfo(
        rows = listOf(
            DebugInfoRow("Package", installedAppInfo.packageName),
            DebugInfoRow("Version", "${installedAppInfo.versionName} (${installedAppInfo.versionCode})"),
            DebugInfoRow("Android", "${deviceSnapshot.androidRelease} (SDK ${deviceSnapshot.sdkInt})"),
            DebugInfoRow("Device", "${deviceSnapshot.manufacturer} ${deviceSnapshot.model}".trim()),
            DebugInfoRow("Target SDK", installedAppInfo.targetSdk.toString()),
            DebugInfoRow("Min SDK", installedAppInfo.minSdk.toString()),
            DebugInfoRow("Crash DB", crashDatabasePath),
            DebugInfoRow("Tunnel Catalog", tunnelCatalogPath),
        ),
    )
}

fun shareCrashLogEntry(context: Context, entry: CrashLogEntry) {
    val intent = Intent(Intent.ACTION_SEND)
        .setType("text/plain")
        .putExtra(Intent.EXTRA_SUBJECT, "vless-tun crash ${entry.id}")
        .putExtra(Intent.EXTRA_TEXT, formatCrashLogEntry(entry))

    val chooser = Intent.createChooser(intent, "Share crash report")
    if (context !is Activity) {
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(chooser)
}

fun formatCrashHandledAt(epochMillis: Long): String {
    return Instant.ofEpochMilli(epochMillis)
        .atZone(ZoneId.systemDefault())
        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
}

fun formatCrashLogEntry(entry: CrashLogEntry): String {
    return buildString {
        appendLine("Handled at: ${formatCrashHandledAt(entry.handledAtEpochMillis)}")
        appendLine("Exception: ${entry.exceptionClass}")
        if (entry.exceptionMessage.isNotBlank()) {
            appendLine("Message: ${entry.exceptionMessage}")
        }
        appendLine("Thread: ${entry.threadName}")
        appendLine("App: ${entry.packageName} ${entry.appVersionName} (${entry.appVersionCode})")
        appendLine("Device: ${entry.deviceManufacturer} ${entry.deviceModel}")
        appendLine("Android: ${entry.androidRelease} (SDK ${entry.sdkInt})")
        appendLine()
        append(entry.stackTrace)
    }.trim()
}

private fun Throwable.renderStackTrace(): String {
    val writer = StringWriter()
    PrintWriter(writer).use { printer ->
        printStackTrace(printer)
    }
    return writer.toString().trim()
}

private const val TAG = "AppDiagnostics"
