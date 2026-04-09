package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

@Composable
internal fun TunnelEgressCard(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.EGRESS_CARD),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "Egress Check",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = "Capture direct IP first, then connect and capture tunneled IP from the same app. That is the automation-friendly proof that traffic actually moved.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_REFRESH_BUTTON),
                enabled = !state.egress.isLoading,
                onClick = { onAction(TunnelHomeAction.RefreshEgressClicked) },
            ) {
                Text(if (state.egress.isLoading) "Checking..." else "Check Egress")
            }
            TunnelMetaLine(
                label = "Direct egress",
                value = state.egress.directObservation?.summary() ?: "Not captured yet",
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_DIRECT_VALUE),
            )
            TunnelMetaLine(
                label = "Tunnel egress",
                value = state.egress.tunneledObservation?.summary() ?: "Not captured yet",
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_TUNNEL_VALUE),
            )
            Text(
                text = state.egress.comparisonLabel,
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_COMPARISON_VALUE),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = state.egress.lastModeLabel,
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_LAST_MODE_VALUE),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            state.egress.error?.let { error ->
                Text(
                    text = error,
                    modifier = Modifier.testTag(TunnelHomeTags.EGRESS_ERROR_VALUE),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}
