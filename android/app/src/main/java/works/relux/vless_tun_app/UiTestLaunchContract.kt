package works.relux.vless_tun_app

import android.content.Intent

object UiTestLaunchContract {
    const val EXTRA_ACTION = "ui_test_action"
    const val EXTRA_LAYOUT = "ui_test_layout"

    const val ACTION_NONE = ""
    const val ACTION_OPEN_CREATE_EDITOR = "open_create_editor"
    const val ACTION_OPEN_EDIT_SELECTED_EDITOR = "open_edit_selected_editor"

    const val LAYOUT_DEFAULT = ""
    const val LAYOUT_EDITOR_PINNED_TOP = "editor_pinned_top"
}

data class UiTestLaunchConfig(
    val action: String = UiTestLaunchContract.ACTION_NONE,
    val editorPinnedTop: Boolean = false,
) {
    companion object {
        fun fromIntent(intent: Intent?): UiTestLaunchConfig {
            val action = intent?.getStringExtra(UiTestLaunchContract.EXTRA_ACTION).orEmpty()
            val layout = intent?.getStringExtra(UiTestLaunchContract.EXTRA_LAYOUT).orEmpty()
            return UiTestLaunchConfig(
                action = action,
                editorPinnedTop = layout == UiTestLaunchContract.LAYOUT_EDITOR_PINNED_TOP,
            )
        }
    }
}
