package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

@Composable
internal fun TunnelHomePage(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
    editorPinnedTop: Boolean,
    contentPadding: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .consumeWindowInsets(contentPadding)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp)
            .testTag(TunnelHomeTags.SCREEN),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        TunnelHeaderBlock()
        if (editorPinnedTop && state.editor.isVisible) {
            TunnelEditorCard(state = state.editor, onAction = onAction)
        } else {
            TunnelStatusCard(state = state)
            TunnelPrimaryActions(state = state, onAction = onAction)
            TunnelEgressCard(state = state, onAction = onAction)
            TunnelCatalogCard(state = state, onAction = onAction)
            TunnelConfigPreviewCard(state = state)
        }
    }
}
