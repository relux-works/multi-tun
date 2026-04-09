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
