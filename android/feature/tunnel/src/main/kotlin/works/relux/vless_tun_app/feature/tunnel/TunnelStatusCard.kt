package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
internal fun TunnelStatusCard(state: TunnelHomeState) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.STATUS_CARD),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = state.phase.name,
                modifier = Modifier.testTag(TunnelHomeTags.STATUS_PHASE),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = state.detail,
                modifier = Modifier.testTag(TunnelHomeTags.STATUS_DETAIL),
                style = MaterialTheme.typography.bodyMedium,
            )
            TunnelMetaLine(
                label = "Selected tunnel",
                value = state.profileName,
                modifier = Modifier.testTag(TunnelHomeTags.STATUS_SELECTED_TUNNEL),
            )
            TunnelMetaLine(
                label = "Endpoint",
                value = state.profileEndpoint,
                modifier = Modifier.testTag(TunnelHomeTags.STATUS_ENDPOINT),
            )
            TunnelMetaLine(
                label = "Source mode",
                value = state.profileSourceSummary,
                modifier = Modifier.testTag(TunnelHomeTags.STATUS_SOURCE_SUMMARY),
            )
            if (state.requiresPermission) {
                Text(
                    text = "Next step: approve Android VPN consent and retry connect.",
                    modifier = Modifier.testTag(TunnelHomeTags.STATUS_PERMISSION_HINT),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
        }
    }
}

@Composable
internal fun TunnelPrimaryActions(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(
            modifier = Modifier
                .weight(1f)
                .testTag(TunnelHomeTags.PRIMARY_BUTTON),
            onClick = { onAction(TunnelHomeAction.PrimaryButtonClicked) },
        ) {
            Text(state.primaryButtonLabel)
        }
        Button(
            modifier = Modifier
                .weight(1f)
                .testTag(TunnelHomeTags.ADD_BUTTON),
            onClick = { onAction(TunnelHomeAction.AddTunnelClicked) },
        ) {
            Text("Add Tunnel")
        }
    }
}
