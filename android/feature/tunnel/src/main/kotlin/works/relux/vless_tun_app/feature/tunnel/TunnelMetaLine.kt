package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
internal fun TunnelMetaLine(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = "$label: $value",
        modifier = modifier,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
