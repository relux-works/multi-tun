package works.relux.vless_tun_app.diagnostics

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import works.relux.vless_tun_app.core.persistence.CrashLogEntry

enum class DebugMenuPage(
    val title: String,
) {
    AppInfo("App Info"),
    Exceptions("Exceptions"),
}

object DebugMenuTags {
    const val SHEET = "Debug_Menu_Sheet"
    const val TAB_APP_INFO = "Debug_Menu_Tab_AppInfo"
    const val TAB_EXCEPTIONS = "Debug_Menu_Tab_Exceptions"
    const val APP_INFO_LIST = "Debug_Menu_AppInfo_List"
    const val EXCEPTIONS_LIST = "Debug_Menu_Exceptions_List"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DebugMenuSheet(
    appInfo: AppDebugInfo,
    crashEntries: List<CrashLogEntry>,
    isLoadingExceptions: Boolean,
    selectedPage: DebugMenuPage,
    onPageSelected: (DebugMenuPage) -> Unit,
    onShareCrashEntry: (CrashLogEntry) -> Unit,
    canDismiss: () -> Boolean = { true },
    onDismiss: () -> Unit,
) {
    val latestCanDismiss by rememberUpdatedState(canDismiss)
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { targetValue ->
            targetValue != SheetValue.Hidden || latestCanDismiss()
        },
    )
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(DebugMenuTags.SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Debug Menu",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
            )
            TabRow(selectedTabIndex = selectedPage.ordinal) {
                DebugMenuPage.entries.forEach { page ->
                    Tab(
                        selected = selectedPage == page,
                        onClick = { onPageSelected(page) },
                        text = { Text(page.title) },
                        modifier = Modifier.testTag(
                            when (page) {
                                DebugMenuPage.AppInfo -> DebugMenuTags.TAB_APP_INFO
                                DebugMenuPage.Exceptions -> DebugMenuTags.TAB_EXCEPTIONS
                            },
                        ),
                    )
                }
            }
            when (selectedPage) {
                DebugMenuPage.AppInfo -> AppInfoPage(appInfo = appInfo)
                DebugMenuPage.Exceptions -> ExceptionsPage(
                    crashEntries = crashEntries,
                    isLoading = isLoadingExceptions,
                    onShareCrashEntry = onShareCrashEntry,
                )
            }
        }
    }
}

@Composable
private fun AppInfoPage(
    appInfo: AppDebugInfo,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 520.dp)
            .testTag(DebugMenuTags.APP_INFO_LIST),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(
            items = appInfo.rows,
            key = { row -> row.label },
        ) { row ->
            Card {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = row.label,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = row.value,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun ExceptionsPage(
    crashEntries: List<CrashLogEntry>,
    isLoading: Boolean,
    onShareCrashEntry: (CrashLogEntry) -> Unit,
) {
    when {
        isLoading -> {
            Text(
                text = "Loading crash history...",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 16.dp),
            )
        }

        crashEntries.isEmpty() -> {
            Text(
                text = "No stored exceptions yet.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 16.dp),
            )
        }

        else -> {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 520.dp)
                    .testTag(DebugMenuTags.EXCEPTIONS_LIST),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(
                    items = crashEntries,
                    key = { entry -> entry.id },
                ) { entry ->
                    Card {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Top,
                            ) {
                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Text(
                                        text = formatCrashHandledAt(entry.handledAtEpochMillis),
                                        style = MaterialTheme.typography.labelLarge,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                    Text(
                                        text = entry.exceptionClass,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                                TextButton(onClick = { onShareCrashEntry(entry) }) {
                                    Text("Share")
                                }
                            }
                            Text(
                                text = entry.exceptionMessage.ifBlank { "No exception message." },
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                text = entry.stackTrace.lineSequence().firstOrNull().orEmpty(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }
    }
}
