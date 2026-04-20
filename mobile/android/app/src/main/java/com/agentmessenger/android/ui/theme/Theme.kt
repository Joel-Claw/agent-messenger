package com.agentmessenger.android.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// CoreScope-inspired dark theme colors
private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF58A6FF),        // Accent blue
    onPrimary = Color(0xFF0033AA),       // Navy
    primaryContainer = Color(0xFF0033AA),
    onPrimaryContainer = Color(0xFFD0E4FF),
    secondary = Color(0xFF58A6FF),
    onSecondary = Color(0xFF001F34),
    secondaryContainer = Color(0xFF1A2E40),
    onSecondaryContainer = Color(0xFFCCE5FF),
    tertiary = Color(0xFF58A6FF),
    background = Color(0xFF0D1117),
    onBackground = Color(0xFFE6EDF3),
    surface = Color(0xFF161B22),
    onSurface = Color(0xFFE6EDF3),
    surfaceVariant = Color(0xFF1C2128),
    onSurfaceVariant = Color(0xFF8B949E),
    outline = Color(0xFF30363D),
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF0033AA),         // Navy
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD0E4FF),
    onPrimaryContainer = Color(0xFF001D3D),
    secondary = Color(0xFF0033AA),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD0E4FF),
    onSecondaryContainer = Color(0xFF001D3D),
    tertiary = Color(0xFF58A6FF),
    background = Color(0xFFF8FAFC),
    onBackground = Color(0xFF0D1117),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF0D1117),
    surfaceVariant = Color(0xFFE6EDF3),
    onSurfaceVariant = Color(0xFF57606A),
    outline = Color(0xFFD0D7DE),
)

@Composable
fun AgentMessengerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}