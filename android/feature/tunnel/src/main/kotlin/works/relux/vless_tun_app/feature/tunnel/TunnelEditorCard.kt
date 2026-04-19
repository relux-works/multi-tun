package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.clickable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Button
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import works.relux.vless_tun_app.core.model.TunnelAppScopeMode

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TunnelEditorCard(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
    modifier: Modifier = Modifier,
    showTitle: Boolean = true,
    showCancelButton: Boolean = true,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.EDITOR_CARD),
    ) {
        val trimmedSource = state.sourceUrl.trim()
        val detectedSourceLabel = when {
            trimmedSource.startsWith("vless://", ignoreCase = true) -> "Detected: inline VLESS URI"
            trimmedSource.startsWith("https://", ignoreCase = true) -> "Detected: subscription URL"
            trimmedSource.startsWith("http://", ignoreCase = true) -> "Detected: insecure source URL"
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
            trimmedSource.startsWith("https://", ignoreCase = true) -> {
                    "The app will fetch and resolve this subscription on every connect."
                }
            trimmedSource.startsWith("http://", ignoreCase = true) -> {
                "HTTP source URLs are not supported. Use https:// or a direct vless:// URI."
            }
            else -> {
                "Paste one HTTPS subscription URL or one direct `vless://` URI here. Leave it empty to use the manual endpoint fields below."
            }
        }
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (showTitle) {
                Text(
                    text = state.title,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
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
                    text = "Source field is empty, so manual endpoint fields are shown below. TLS is enabled automatically for manual endpoints.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
            if (state.showManualEndpointFields) {
                Text(
                    text = "Manual Endpoint (TLS)",
                    style = MaterialTheme.typography.labelLarge,
                )
                Text(
                    text = "Manual endpoints are saved with TLS enabled. Use server name / SNI that matches the endpoint certificate.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
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
            Text(
                text = "Apps",
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = "Choose whether selected apps bypass the tunnel or are the only apps that use it. If no apps are selected, the tunnel applies to all apps.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = state.appScopeMode == TunnelAppScopeMode.Blacklist,
                    onClick = { onAction(TunnelHomeAction.EditorAppScopeModeChanged(TunnelAppScopeMode.Blacklist)) },
                    label = { Text("Blacklist") },
                    modifier = Modifier.testTag(TunnelHomeTags.EDITOR_APP_SCOPE_MODE_BLACKLIST),
                )
                FilterChip(
                    selected = state.appScopeMode == TunnelAppScopeMode.Whitelist,
                    onClick = { onAction(TunnelHomeAction.EditorAppScopeModeChanged(TunnelAppScopeMode.Whitelist)) },
                    label = { Text("Whitelist") },
                    modifier = Modifier.testTag(TunnelHomeTags.EDITOR_APP_SCOPE_MODE_WHITELIST),
                )
            }
            Text(
                text = state.appScopeSummary,
                modifier = Modifier.testTag(TunnelHomeTags.EDITOR_APP_SCOPE_SUMMARY),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.normalizedAppPackages.isNotEmpty()) {
                val packageToLabel = state.installedApps.associateBy(
                    keySelector = { app -> app.packageName },
                    valueTransform = { app -> app.label },
                )
                Text(
                    text = state.normalizedAppPackages.joinToString(separator = "\n") { packageName ->
                        packageToLabel[packageName]?.let { label -> "$label\n$packageName" } ?: packageName
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(modifier = Modifier.weight(1f)) {
                    Button(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(TunnelHomeTags.EDITOR_APP_SCOPE_PICKER_BUTTON),
                        onClick = { onAction(TunnelHomeAction.EditorOpenAppPickerClicked) },
                    ) {
                        Text(if (state.normalizedAppPackages.isEmpty()) "Choose Apps" else "Edit Apps")
                    }
                }
                Box(modifier = Modifier.weight(1f)) {
                    TextButton(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(TunnelHomeTags.EDITOR_APP_SCOPE_CLEAR_BUTTON),
                        onClick = { onAction(TunnelHomeAction.EditorClearSelectedAppsClicked) },
                    ) {
                        Text("Clear")
                    }
                }
            }
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
                if (showCancelButton) {
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
    if (state.isAppPickerVisible) {
        TunnelAppPickerSheet(
            state = state,
            onAction = onAction,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnelAppPickerSheet(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    val query = state.appPickerQuery.trim()
    val filteredApps = if (query.isBlank()) {
        state.installedApps
    } else {
        state.installedApps.filter { app ->
            app.label.contains(query, ignoreCase = true) ||
                app.packageName.contains(query, ignoreCase = true)
        }
    }

    ModalBottomSheet(
        onDismissRequest = { onAction(TunnelHomeAction.EditorDismissAppPickerClicked) },
        modifier = Modifier.testTag(TunnelHomeTags.EDITOR_APP_PICKER_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Choose Apps",
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = when (state.appScopeMode) {
                    TunnelAppScopeMode.Blacklist -> "Selected apps stay direct and bypass the tunnel."
                    TunnelAppScopeMode.Whitelist -> "Only selected apps use the tunnel."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.appPickerQuery,
                onValueChange = { onAction(TunnelHomeAction.EditorAppPickerQueryChanged(it)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_APP_PICKER_QUERY),
                label = { Text("Search apps") },
                singleLine = true,
            )
            when {
                state.isLoadingInstalledApps -> {
                    Text(
                        text = "Loading installed apps...",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }

                filteredApps.isEmpty() -> {
                    Text(
                        text = if (state.installedApps.isEmpty()) {
                            "No launchable apps found."
                        } else {
                            "No apps match the current search."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }

                else -> {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 520.dp)
                            .testTag(TunnelHomeTags.EDITOR_APP_PICKER_LIST),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(
                            items = filteredApps,
                            key = { app -> app.packageName },
                        ) { app ->
                            val isSelected = state.normalizedAppPackages.contains(app.packageName)
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag(TunnelHomeTags.editorAppPickerItem(app.packageName))
                                    .clickable {
                                        onAction(TunnelHomeAction.EditorAppSelectionToggled(app.packageName))
                                    },
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp, vertical = 12.dp),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Column(
                                        modifier = Modifier.weight(1f),
                                        verticalArrangement = Arrangement.spacedBy(4.dp),
                                    ) {
                                        Text(
                                            text = app.label,
                                            style = MaterialTheme.typography.bodyLarge,
                                        )
                                        Text(
                                            text = app.packageName,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    Checkbox(
                                        checked = isSelected,
                                        onCheckedChange = {
                                            onAction(TunnelHomeAction.EditorAppSelectionToggled(app.packageName))
                                        },
                                    )
                                }
                            }
                        }
                    }
                }
            }
            TextButton(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(TunnelHomeTags.EDITOR_APP_PICKER_DONE_BUTTON),
                onClick = { onAction(TunnelHomeAction.EditorDismissAppPickerClicked) },
            ) {
                Text("Done")
            }
        }
    }
}
