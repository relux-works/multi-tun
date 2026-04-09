package works.relux.vless_tun_app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF0F766E),
    onPrimary = Color(0xFFFFFFFF),
    secondary = Color(0xFF155E75),
    onSecondary = Color(0xFFFFFFFF),
    background = Color(0xFFF6FAFB),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111827),
    tertiary = Color(0xFFB45309),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF5EEAD4),
    onPrimary = Color(0xFF042F2E),
    secondary = Color(0xFF67E8F9),
    onSecondary = Color(0xFF082F49),
    background = Color(0xFF09131A),
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF10202A),
    onSurface = Color(0xFFE5EEF5),
    tertiary = Color(0xFFFBBF24),
)

@Composable
fun VlessTunTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
