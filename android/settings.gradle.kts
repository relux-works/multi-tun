import java.util.Properties

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

fun resolveAndroidSdkPath(): String? {
    System.getProperty("android.home")?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }

    val localPropertiesFile = file("local.properties")
    if (localPropertiesFile.exists()) {
        val localProperties = Properties()
        localPropertiesFile.inputStream().use(localProperties::load)
        localProperties.getProperty("sdk.dir")?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
    }

    return System.getenv("ANDROID_HOME")?.trim()?.takeIf { it.isNotEmpty() }
        ?: System.getenv("ANDROID_SDK_ROOT")?.trim()?.takeIf { it.isNotEmpty() }
}

resolveAndroidSdkPath()?.let { sdkPath ->
    System.setProperty("android.home", sdkPath)
}

includeBuild("../../relux-works/skill-android-testing-tools/toolkit")
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "vless-tun-app"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
include(":app")
include(":core:mvi")
include(":core:model")
include(":core:persistence")
include(":core:render")
include(":core:runtime-contract")
include(":core:subscription")
include(":observer")
include(":feature:tunnel")
include(":platform:singbox")
include(":platform:vpnservice")
