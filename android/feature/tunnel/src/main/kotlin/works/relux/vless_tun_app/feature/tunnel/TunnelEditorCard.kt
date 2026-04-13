package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

@Composable
internal fun TunnelEditorCard(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.EDITOR_CARD),
    ) {
        val trimmedSource = state.sourceUrl.trim()
        val detectedSourceLabel = when {
            trimmedSource.startsWith("vless://", ignoreCase = true) -> "Detected: inline VLESS URI"
            trimmedSource.startsWith("http://", ignoreCase = true) ||
                trimmedSource.startsWith("https://", ignoreCase = true) -> "Detected: subscription URL"
            trimmedSource.isBlank() -> "Detected: manual endpoint"
            else -> "Detected: source URL"
        }
        val sourcePlaceholder = if (trimmedSource.startsWith("vless://", ignoreCase = true)) {
            "vless://uuid@host:port?type=grpc&sni=edge.example.com"
        } else {
            "https://subscription.example/path or vless://uuid@host:port?type=grpc"
        }
        val sourceDescription = when {
            trimmedSource.startsWith("vless://", ignoreCase = true) -> {
                "The app will parse this inline VLESS URI directly at preview/connect time."
            }
            trimmedSource.startsWith("http://", ignoreCase = true) ||
                trimmedSource.startsWith("https://", ignoreCase = true) -> {
                    "The app will fetch and resolve this subscription on every connect."
                }
            else -> {
                "Paste one subscription URL or one direct `vless://` URI here. Leave it empty to use the manual endpoint fields below."
            }
        }
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = state.title,
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = "Normal flow: paste one subscription URL or one direct `vless://` URI, save, then connect.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.name,
                onValueChange = { onAction(TunnelHomeAction.EditorNameChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_NAME_INPUT),
                label = { Text("Tunnel Name") },
                singleLine = true,
            )
            Text(
                text = "Connection Source",
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = detectedSourceLabel,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.sourceUrl,
                onValueChange = { onAction(TunnelHomeAction.EditorSourceUrlChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_SOURCE_URL_INPUT),
                label = { Text("Source URL or inline VLESS") },
                placeholder = { Text(sourcePlaceholder) },
                singleLine = true,
            )
            Text(
                text = sourceDescription,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.sourceUrl.isBlank()) {
                Text(
                    text = "Source field is empty, so manual endpoint fields are shown below.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
            if (state.showManualEndpointFields) {
                Text(
                    text = "Manual Endpoint",
                    style = MaterialTheme.typography.labelLarge,
                )
                OutlinedTextField(
                    value = state.host,
                    onValueChange = { onAction(TunnelHomeAction.EditorHostChanged(it)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(TunnelHomeTags.EDITOR_HOST_INPUT),
                    label = { Text("Host") },
                    singleLine = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.port,
                        onValueChange = { onAction(TunnelHomeAction.EditorPortChanged(it)) },
                        modifier = Modifier
                            .weight(1f)
                            .testTag(TunnelHomeTags.EDITOR_PORT_INPUT),
                        label = { Text("Port") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.transport,
                        onValueChange = { onAction(TunnelHomeAction.EditorTransportChanged(it)) },
                        modifier = Modifier
                            .weight(1f)
                            .testTag(TunnelHomeTags.EDITOR_TRANSPORT_INPUT),
                        label = { Text("Transport") },
                        singleLine = true,
                    )
                }
                OutlinedTextField(
                    value = state.serverName,
                    onValueChange = { onAction(TunnelHomeAction.EditorServerNameChanged(it)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(TunnelHomeTags.EDITOR_SERVER_NAME_INPUT),
                    label = { Text("Server Name / SNI") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.uuid,
                    onValueChange = { onAction(TunnelHomeAction.EditorUuidChanged(it)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(TunnelHomeTags.EDITOR_UUID_INPUT),
                    label = { Text("UUID") },
                    singleLine = true,
                )
            }
            Text(
                text = "Routing Masks",
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = "One mask per line. Example: corp.example or .ru. If this list is empty, the tunnel stays full-tunnel except for bypasses below.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.routeMasksText,
                onValueChange = { onAction(TunnelHomeAction.EditorRouteMasksChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_ROUTE_MASKS_INPUT),
                label = { Text("Route via Tunnel") },
                placeholder = { Text("ipify.org\ncorp.example") },
                minLines = 3,
            )
            Text(
                text = "Bypass masks win when both lists match the same destination.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.bypassMasksText,
                onValueChange = { onAction(TunnelHomeAction.EditorBypassMasksChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_BYPASS_MASKS_INPUT),
                label = { Text("Bypass Tunnel") },
                placeholder = { Text("api64.ipify.org\n.telegram.org") },
                minLines = 3,
            )
            state.validationError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(modifier = Modifier.weight(1f)) {
                    Button(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(TunnelHomeTags.EDITOR_SAVE_BUTTON),
                        onClick = { onAction(TunnelHomeAction.SaveTunnelClicked) },
                    ) {
                        Text("Save")
                    }
                }
                Box(modifier = Modifier.weight(1f)) {
                    TextButton(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(TunnelHomeTags.EDITOR_CANCEL_BUTTON),
                        onClick = { onAction(TunnelHomeAction.DismissEditorClicked) },
                    ) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
}
