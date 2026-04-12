package works.relux.vless_tun_app.core.persistence

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase

data class CrashLogWrite(
    val handledAtEpochMillis: Long,
    val threadName: String,
    val exceptionClass: String,
    val exceptionMessage: String,
    val stackTrace: String,
    val packageName: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val deviceManufacturer: String,
    val deviceModel: String,
    val androidRelease: String,
    val sdkInt: Int,
)

data class CrashLogEntry(
    val id: Long,
    val handledAtEpochMillis: Long,
    val threadName: String,
    val exceptionClass: String,
    val exceptionMessage: String,
    val stackTrace: String,
    val packageName: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val deviceManufacturer: String,
    val deviceModel: String,
    val androidRelease: String,
    val sdkInt: Int,
)

class CrashLogStore(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val database = database(appContext)

    fun warmUp() {
        database.openHelper.writableDatabase
    }

    fun record(write: CrashLogWrite) {
        database.crashLogDao().insert(CrashLogEntity.fromWrite(write))
    }

    fun listRecent(limit: Int = DEFAULT_LIMIT): List<CrashLogEntry> {
        return database.crashLogDao()
            .listRecent(limit)
            .map(CrashLogEntity::toModel)
    }

    fun clear() {
        database.crashLogDao().deleteAll()
    }

    fun databasePath(): String = appContext.getDatabasePath(DATABASE_NAME).absolutePath

    private companion object {
        private const val DATABASE_NAME = "crash-log.db"
        private const val DEFAULT_LIMIT = 100

        @Volatile
        private var instance: CrashLogDatabase? = null

        fun database(context: Context): CrashLogDatabase {
            return instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context,
                    CrashLogDatabase::class.java,
                    DATABASE_NAME,
                )
                    .fallbackToDestructiveMigration()
                    .allowMainThreadQueries()
                    .build()
                    .also { created -> instance = created }
            }
        }
    }
}

@Entity(tableName = "crash_logs")
internal data class CrashLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    @ColumnInfo(name = "handled_at_epoch_millis")
    val handledAtEpochMillis: Long,
    @ColumnInfo(name = "thread_name")
    val threadName: String,
    @ColumnInfo(name = "exception_class")
    val exceptionClass: String,
    @ColumnInfo(name = "exception_message")
    val exceptionMessage: String,
    @ColumnInfo(name = "stack_trace")
    val stackTrace: String,
    @ColumnInfo(name = "package_name")
    val packageName: String,
    @ColumnInfo(name = "app_version_name")
    val appVersionName: String,
    @ColumnInfo(name = "app_version_code")
    val appVersionCode: Long,
    @ColumnInfo(name = "device_manufacturer")
    val deviceManufacturer: String,
    @ColumnInfo(name = "device_model")
    val deviceModel: String,
    @ColumnInfo(name = "android_release")
    val androidRelease: String,
    @ColumnInfo(name = "sdk_int")
    val sdkInt: Int,
) {
    fun toModel(): CrashLogEntry {
        return CrashLogEntry(
            id = id,
            handledAtEpochMillis = handledAtEpochMillis,
            threadName = threadName,
            exceptionClass = exceptionClass,
            exceptionMessage = exceptionMessage,
            stackTrace = stackTrace,
            packageName = packageName,
            appVersionName = appVersionName,
            appVersionCode = appVersionCode,
            deviceManufacturer = deviceManufacturer,
            deviceModel = deviceModel,
            androidRelease = androidRelease,
            sdkInt = sdkInt,
        )
    }

    companion object {
        fun fromWrite(write: CrashLogWrite): CrashLogEntity {
            return CrashLogEntity(
                handledAtEpochMillis = write.handledAtEpochMillis,
                threadName = write.threadName,
                exceptionClass = write.exceptionClass,
                exceptionMessage = write.exceptionMessage,
                stackTrace = write.stackTrace,
                packageName = write.packageName,
                appVersionName = write.appVersionName,
                appVersionCode = write.appVersionCode,
                deviceManufacturer = write.deviceManufacturer,
                deviceModel = write.deviceModel,
                androidRelease = write.androidRelease,
                sdkInt = write.sdkInt,
            )
        }
    }
}

@Dao
internal interface CrashLogDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(entity: CrashLogEntity): Long

    @Query(
        """
        SELECT * FROM crash_logs
        ORDER BY handled_at_epoch_millis DESC, id DESC
        LIMIT :limit
        """,
    )
    fun listRecent(limit: Int): List<CrashLogEntity>

    @Query("DELETE FROM crash_logs")
    fun deleteAll()
}

@Database(
    entities = [CrashLogEntity::class],
    version = 1,
    exportSchema = false,
)
internal abstract class CrashLogDatabase : RoomDatabase() {
    abstract fun crashLogDao(): CrashLogDao
}
