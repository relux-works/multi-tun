package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

@Composable
internal fun TunnelEditorScreen(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
) {
    var isDeleteDialogVisible by remember(state.profileId) { mutableStateOf(false) }

    Scaffold(
        modifier = Modifier.testTag(TunnelHomeTags.EDITOR_SCREEN),
        topBar = {
            TunnelEditorTopBar(
                state = state,
                onBack = { onAction(TunnelHomeAction.DismissEditorClicked) },
                onDelete = { isDeleteDialogVisible = true },
            )
        },
    ) { contentPadding ->
        TunnelEditorPage(
            state = state,
            onAction = onAction,
            contentPadding = contentPadding,
        )
    }

    if (state.mode == TunnelEditorMode.Edit && isDeleteDialogVisible) {
        AlertDialog(
            onDismissRequest = { isDeleteDialogVisible = false },
            title = { Text("Delete Tunnel") },
            text = {
                Text("Delete '${state.name}' from the saved tunnel catalog?")
            },
            confirmButton = {
                TextButton(
                    modifier = Modifier.testTag(TunnelHomeTags.EDITOR_DELETE_CONFIRM_BUTTON),
                    onClick = {
                        isDeleteDialogVisible = false
                        onAction(TunnelHomeAction.DeleteEditedTunnelClicked)
                    },
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { isDeleteDialogVisible = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TunnelEditorTopBar(
    state: TunnelEditorState,
    onBack: () -> Unit,
    onDelete: () -> Unit,
) {
    CenterAlignedTopAppBar(
        modifier = Modifier.testTag(TunnelHomeTags.EDITOR_TOP_BAR),
        title = {
            Text(state.title)
        },
        navigationIcon = {
            TextButton(
                modifier = Modifier.testTag(TunnelHomeTags.EDITOR_BACK_BUTTON),
                onClick = onBack,
            ) {
                Text("Back")
            }
        },
        actions = {
            if (state.mode == TunnelEditorMode.Edit) {
                TextButton(
                    modifier = Modifier.testTag(TunnelHomeTags.EDITOR_DELETE_BUTTON),
                    onClick = onDelete,
                ) {
                    Text("Delete")
                }
            }
        },
    )
}

@Composable
private fun TunnelEditorPage(
    state: TunnelEditorState,
    onAction: (TunnelHomeAction) -> Unit,
    contentPadding: PaddingValues,
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
    ) {
        TunnelEditorCard(
            state = state,
            onAction = onAction,
            showTitle = false,
            showCancelButton = false,
            modifier = Modifier
                .padding(contentPadding)
                .padding(horizontal = 20.dp, vertical = 16.dp)
                .imePadding()
                .verticalScroll(rememberScrollState()),
        )
    }
}
