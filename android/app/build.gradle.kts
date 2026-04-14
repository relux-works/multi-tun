import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.triplet.play)
}

fun loadLocalProperties(file: File): Properties =
    Properties().apply {
        if (file.exists()) {
            FileInputStream(file).use(::load)
        }
    }

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = loadLocalProperties(keystorePropertiesFile)

fun localProperty(name: String): String? =
    keystoreProperties.getProperty(name)?.trim()?.takeIf { it.isNotEmpty() }

val releaseStoreFilePath = localProperty("storeFile")
val releaseKeyAlias = localProperty("keyAlias")
val releaseStorePassword =
    providers.environmentVariable("VLESS_TUN_ANDROID_STORE_PASSWORD").orNull?.trim()?.takeIf { it.isNotEmpty() }
        ?: localProperty("storePassword")
val releaseKeyPassword =
    providers.environmentVariable("VLESS_TUN_ANDROID_KEY_PASSWORD").orNull?.trim()?.takeIf { it.isNotEmpty() }
        ?: localProperty("keyPassword")

val releaseSigningReady =
    !releaseStoreFilePath.isNullOrEmpty() &&
        !releaseKeyAlias.isNullOrEmpty() &&
        !releaseStorePassword.isNullOrEmpty() &&
        !releaseKeyPassword.isNullOrEmpty()

val wantsReleaseTask = gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }
if (wantsReleaseTask && !releaseSigningReady) {
    throw GradleException(
        """
        Missing Android release signing metadata or secrets.
        Expected:
          - android/keystore.properties with storeFile + keyAlias
          - VLESS_TUN_ANDROID_STORE_PASSWORD
          - VLESS_TUN_ANDROID_KEY_PASSWORD

        Use the Go helper:
          android-release setup
          android-release generate-keystore
          android-release bundle
        """.trimIndent()
    )
}

val playTrack =
    providers.gradleProperty("VLESS_TUN_ANDROID_PLAY_TRACK")
        .orElse(providers.environmentVariable("VLESS_TUN_ANDROID_PLAY_TRACK"))
        .orElse("internal")

android {
    namespace = "works.relux.vless_tun_app"
	compileSdk = 36

    defaultConfig {
        applicationId = "works.relux.android.vlesstun.app"
        minSdk = 33
        targetSdk = 35
        versionCode = 9
        versionName = "1.0.9"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningReady) {
            create("release") {
                storeFile = rootProject.file(requireNotNull(releaseStoreFilePath))
                storePassword = releaseStorePassword
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            ndk {
                // Keep Play symbolication useful without shipping full native debug info.
                debugSymbolLevel = "SYMBOL_TABLE"
            }
            if (releaseSigningReady) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

play {
    defaultToAppBundles.set(true)
    track.set(playTrack)
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(platform(libs.androidx.compose.bom))

    implementation(project(":core:mvi"))
    implementation(project(":core:model"))
    implementation(project(":core:persistence"))
    implementation(project(":core:render"))
    implementation(project(":core:runtime-contract"))
    implementation(project(":core:subscription"))
    implementation(project(":feature:tunnel"))
    implementation(project(":platform:singbox"))
    implementation(project(":platform:xray"))
    implementation(project(":platform:vpnservice"))

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.material)
    implementation(libs.okhttp)

    testImplementation(libs.junit)
    androidTestImplementation("com.uitesttools:screenshot-kit:0.0.1")
    androidTestImplementation("com.uitesttools:uitest-kit:0.0.1")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.uiautomator)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
