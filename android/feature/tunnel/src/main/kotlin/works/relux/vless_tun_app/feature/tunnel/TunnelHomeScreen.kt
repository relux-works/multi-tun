package works.relux.vless_tun_app.feature.tunnel

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.clickable
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId

@Composable
fun TunnelHomeScreen(
    state: TunnelHomeState,
    onAction: (TunnelHomeAction) -> Unit,
    editorPinnedTop: Boolean = false,
    onHeaderTap: () -> Unit = {},
) {
    Surface(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = true },
    ) {
        Scaffold(
            topBar = { TunnelTopBar(onHeaderTap = onHeaderTap) },
        ) { contentPadding ->
            TunnelHomePage(
                state = state,
                onAction = onAction,
                editorPinnedTop = editorPinnedTop,
                contentPadding = contentPadding,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TunnelTopBar(
    onHeaderTap: () -> Unit,
) {
    CenterAlignedTopAppBar(
        modifier = Modifier
            .testTag(TunnelHomeTags.TOP_BAR)
            .clickable(onClick = onHeaderTap),
        title = {
            Text(
                text = "Tunnel Home",
                modifier = Modifier.testTag(TunnelHomeTags.TITLE),
                style = MaterialTheme.typography.headlineSmall,
            )
        },
    )
}
