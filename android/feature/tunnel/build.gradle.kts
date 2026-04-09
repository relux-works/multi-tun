plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "works.relux.vless_tun_app.feature.tunnel"
    compileSdk = 36

    defaultConfig {
        minSdk = 33
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

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(project(":core:mvi"))
    api(project(":core:model"))
    api(project(":core:runtime-contract"))

    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    testImplementation(libs.junit)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
