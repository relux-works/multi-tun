package works.relux.vless_tun_app.core.persistence

import java.io.File
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import works.relux.vless_tun_app.core.model.TunnelProfile
import works.relux.vless_tun_app.core.model.TunnelSourceMode

data class TunnelCatalog(
    val profiles: List<TunnelProfile>,
    val selectedProfileId: String?,
)

class TunnelCatalogStore(
    private val storageFile: File,
) {
    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    fun load(defaultCatalog: TunnelCatalog): TunnelCatalog {
        if (!storageFile.exists()) {
            save(defaultCatalog)
            return defaultCatalog
        }

        val loadedCatalog = runCatching {
            json.decodeFromString<TunnelCatalogDocument>(storageFile.readText()).toModel()
        }.getOrNull()

        if (loadedCatalog == null || loadedCatalog.profiles.isEmpty()) {
            save(defaultCatalog)
            return defaultCatalog
        }

        val resolvedSelectedId = loadedCatalog.selectedProfileId
            ?.takeIf { selectedId -> loadedCatalog.profiles.any { it.id == selectedId } }
            ?: loadedCatalog.profiles.firstOrNull()?.id

        return loadedCatalog.copy(selectedProfileId = resolvedSelectedId)
    }

    fun save(catalog: TunnelCatalog) {
        storageFile.parentFile?.mkdirs()
        storageFile.writeText(
            json.encodeToString(
                TunnelCatalogDocument.serializer(),
                TunnelCatalogDocument.fromModel(catalog),
            ),
        )
    }

    fun storagePath(): String = storageFile.absolutePath
}

@Serializable
private data class TunnelCatalogDocument(
    val profiles: List<TunnelProfileDocument>,
    val selectedProfileId: String? = null,
) {
    fun toModel(): TunnelCatalog {
        return TunnelCatalog(
            profiles = profiles.map(TunnelProfileDocument::toModel),
            selectedProfileId = selectedProfileId,
        )
    }

    companion object {
        fun fromModel(catalog: TunnelCatalog): TunnelCatalogDocument {
            return TunnelCatalogDocument(
                profiles = catalog.profiles.map(TunnelProfileDocument::fromModel),
                selectedProfileId = catalog.selectedProfileId,
            )
        }
    }
}

@Serializable
private data class TunnelProfileDocument(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val transport: String,
    val sourceMode: String,
    val sourceUrl: String,
    val serverName: String,
    val uuid: String,
) {
    fun toModel(): TunnelProfile {
        val resolvedSourceMode = runCatching {
            TunnelSourceMode.valueOf(sourceMode)
        }.getOrDefault(TunnelSourceMode.ProxyResolver)
        return TunnelProfile(
            id = id,
            name = name,
            host = host,
            port = port,
            transport = transport,
            sourceMode = resolvedSourceMode,
            sourceUrl = sourceUrl,
            serverName = serverName,
            uuid = uuid,
        )
    }

    companion object {
        fun fromModel(profile: TunnelProfile): TunnelProfileDocument {
            return TunnelProfileDocument(
                id = profile.id,
                name = profile.name,
                host = profile.host,
                port = profile.port,
                transport = profile.transport,
                sourceMode = profile.sourceMode.name,
                sourceUrl = profile.sourceUrl,
                serverName = profile.serverName,
                uuid = profile.uuid,
            )
        }
    }
}
