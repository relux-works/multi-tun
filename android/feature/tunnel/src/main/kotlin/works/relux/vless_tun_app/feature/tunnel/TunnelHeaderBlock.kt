package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

@Composable
internal fun TunnelHeaderBlock() {
    Text(
        text = "A lightweight client for your VLESS tunnel. Add a subscription URL or direct endpoint, then connect when you're ready.",
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
