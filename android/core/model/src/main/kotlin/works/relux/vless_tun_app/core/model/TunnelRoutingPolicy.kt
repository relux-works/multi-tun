package works.relux.vless_tun_app.core.model

import java.net.IDN

data class TunnelRoutingPolicy(
    val routeMasks: List<String> = emptyList(),
    val bypassMasks: List<String> = emptyList(),
) {
    fun normalized(): TunnelRoutingPolicy {
        val normalizedBypasses = normalizeSuffixMasks(bypassMasks)
        val normalizedRoutes = subtractCoveredMasks(
            candidates = normalizeSuffixMasks(routeMasks),
            overrides = normalizedBypasses,
        )
        return copy(
            routeMasks = normalizedRoutes,
            bypassMasks = normalizedBypasses,
        )
    }

    val usesRouteAllowList: Boolean
        get() = routeMasks.isNotEmpty()
}

fun TunnelRoutingPolicy.routeMasksText(): String = routeMasks.joinToString("\n")

fun TunnelRoutingPolicy.bypassMasksText(): String = bypassMasks.joinToString("\n")

fun parseSuffixMaskText(raw: String): List<String> {
    return normalizeSuffixMasks(
        raw.split('\n', ',', ';')
            .map(String::trim)
            .filter(String::isNotBlank),
    )
}

fun normalizeSuffixMasks(values: List<String>): List<String> {
    val unique = linkedMapOf<String, String>()
    values.forEach { value ->
        normalizeSuffixMask(value)?.let { normalized ->
            unique.putIfAbsent(maskMatchKey(normalized), normalized)
        }
    }
    return collapseCoveredMasks(unique.values.toList())
}

private fun normalizeSuffixMask(raw: String): String? {
    val trimmed = raw.trim().lowercase()
    if (trimmed.isBlank() || trimmed == ".") {
        return null
    }

    val hasLeadingDot = trimmed.startsWith('.')
    val core = trimmed.trimStart('.')
    if (core.isBlank()) {
        return null
    }

    val ascii = runCatching { IDN.toASCII(core) }.getOrDefault(core)
    return if (hasLeadingDot) {
        ".$ascii"
    } else {
        ascii
    }
}

private fun collapseCoveredMasks(values: List<String>): List<String> {
    return values.filterIndexed { index, value ->
        val normalizedValue = maskMatchKey(value)
        values.indices.none { otherIndex ->
            if (otherIndex == index) {
                return@none false
            }
            val candidate = maskMatchKey(values[otherIndex])
            candidate.isNotBlank() &&
                candidate != normalizedValue &&
                maskCoveredByCandidate(normalizedValue, candidate)
        }
    }
}

private fun subtractCoveredMasks(
    candidates: List<String>,
    overrides: List<String>,
): List<String> {
    if (overrides.isEmpty()) {
        return candidates
    }
    return candidates.filterNot { candidate ->
        val normalizedCandidate = maskMatchKey(candidate)
        overrides.any { override ->
            maskCoveredByCandidate(normalizedCandidate, maskMatchKey(override))
        }
    }
}

private fun maskCoveredByCandidate(
    value: String,
    candidate: String,
): Boolean {
    if (value.isBlank() || candidate.isBlank()) {
        return false
    }
    return value == candidate || value.endsWith(".$candidate")
}

private fun maskMatchKey(value: String): String = value.trim().lowercase().trimStart('.')
