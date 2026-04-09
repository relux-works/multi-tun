package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import works.relux.vless_tun_app.core.model.TunnelSourceMode

@Composable
fun TunnelHomeScreen(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = true },
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 24.dp)
                .testTag(TunnelHomeTags.SCREEN),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            HeaderBlock()
            StatusBlock(state = state)
            PrimaryActions(state = state, onAction = onAction)
            EgressBlock(state = state, onAction = onAction)
            TunnelCatalog(state = state, onAction = onAction)
            if (state.editor.isVisible) {
                TunnelEditor(state = state.editor, onAction = onAction)
            }
            ConfigPreview(state = state)
        }
    }
}

@Composable
private fun EgressBlock(
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
            MetaLine(
                label = "Direct egress",
                value = state.egress.directObservation?.summary() ?: "Not captured yet",
                modifier = Modifier.testTag(TunnelHomeTags.EGRESS_DIRECT_VALUE),
            )
            MetaLine(
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

@Composable
private fun HeaderBlock() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "Tunnel Home",
            modifier = Modifier.testTag(TunnelHomeTags.TITLE),
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            text = "Paste your own subscription or direct VLESS endpoint and keep the runtime strictly TUN-only with zero localhost proxy surface.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun StatusBlock(state: TunnelHomeState) {
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
            MetaLine(label = "Selected tunnel", value = state.profileName)
            MetaLine(label = "Endpoint", value = state.profileEndpoint)
            MetaLine(label = "Source mode", value = state.profileSourceSummary)
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
private fun PrimaryActions(
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

@Composable
private fun TunnelCatalog(
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

@Composable
private fun TunnelEditor(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TunnelHomeTags.EDITOR_CARD),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = state.title,
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = "Normal flow: paste one subscription URL or `vless://` link and save. Manual endpoint fields are only for override cases.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.name,
                onValueChange = { onAction(TunnelHomeAction.EditorNameChanged(it)) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Tunnel Name") },
                singleLine = true,
            )
            Text(
                text = "Source Mode",
                style = MaterialTheme.typography.labelLarge,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TunnelSourceMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.sourceMode == mode,
                        onClick = { onAction(TunnelHomeAction.EditorSourceModeChanged(mode)) },
                        label = { Text(mode.title) },
                    )
                }
            }
            Text(
                text = state.sourceMode.subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.sourceUrl,
                onValueChange = { onAction(TunnelHomeAction.EditorSourceUrlChanged(it)) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Source URL / VLESS URI") },
                placeholder = { Text("https://subscription.example/path or vless://...") },
                singleLine = true,
            )
            Text(
                text = "For the normal case this is the only field you need: paste the app-managed source URL or a direct `vless://` link here.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.sourceUrl.isBlank()) {
                Text(
                    text = "Source URL is empty, so manual endpoint fields are shown below.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            } else {
                TextButton(
                    onClick = { onAction(TunnelHomeAction.EditorManualOverrideToggled) },
                ) {
                    Text(
                        if (state.manualConfigEnabled) {
                            "Hide Manual Endpoint Override"
                        } else {
                            "Show Manual Endpoint Override"
                        },
                    )
                }
            }
            if (state.showManualEndpointFields) {
                Text(
                    text = "Manual Endpoint Override",
                    style = MaterialTheme.typography.labelLarge,
                )
                OutlinedTextField(
                    value = state.host,
                    onValueChange = { onAction(TunnelHomeAction.EditorHostChanged(it)) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Host") },
                    singleLine = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.port,
                        onValueChange = { onAction(TunnelHomeAction.EditorPortChanged(it)) },
                        modifier = Modifier.weight(1f),
                        label = { Text("Port") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.transport,
                        onValueChange = { onAction(TunnelHomeAction.EditorTransportChanged(it)) },
                        modifier = Modifier.weight(1f),
                        label = { Text("Transport") },
                        singleLine = true,
                    )
                }
                OutlinedTextField(
                    value = state.serverName,
                    onValueChange = { onAction(TunnelHomeAction.EditorServerNameChanged(it)) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Server Name / SNI") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.uuid,
                    onValueChange = { onAction(TunnelHomeAction.EditorUuidChanged(it)) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("UUID") },
                    singleLine = true,
                )
            }
            state.validationError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { onAction(TunnelHomeAction.SaveTunnelClicked) },
                ) {
                    Text("Save")
                }
                TextButton(
                    modifier = Modifier.weight(1f),
                    onClick = { onAction(TunnelHomeAction.DismissEditorClicked) },
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

@Composable
private fun ConfigPreview(state: TunnelHomeState) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "Rendered Config Preview",
            style = MaterialTheme.typography.titleMedium,
        )
        SelectionContainer {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(20.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerLow)
                    .padding(16.dp)
                    .testTag(TunnelHomeTags.CONFIG_PREVIEW),
            ) {
                Text(
                    text = state.configPreview,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@Composable
private fun MetaLine(
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
