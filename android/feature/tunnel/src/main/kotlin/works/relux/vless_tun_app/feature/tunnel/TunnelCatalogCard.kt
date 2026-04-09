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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
internal fun TunnelCatalogCard(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.TUNNEL_LIST),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Configured Tunnels",
                style = MaterialTheme.typography.titleMedium,
            )
            state.profiles.forEach { profile ->
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (profile.isSelected) {
                            MaterialTheme.colorScheme.primaryContainer
                        } else {
                            MaterialTheme.colorScheme.surfaceContainerLow
                        },
                    ),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = profile.name,
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                text = profile.transport,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        Text(
                            text = profile.endpoint,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            text = profile.sourceSummary,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    onAction(TunnelHomeAction.SelectTunnelClicked(profile.id))
                                },
                            ) {
                                Text(if (profile.isSelected) "Selected" else "Use")
                            }
                            TextButton(
                                modifier = Modifier.testTag(TunnelHomeTags.TUNNEL_EDIT_BUTTON),
                                onClick = {
                                    onAction(TunnelHomeAction.EditTunnelClicked(profile.id))
                                },
                            ) {
                                Text("Edit")
                            }
                        }
                    }
                }
            }
        }
    }
}
