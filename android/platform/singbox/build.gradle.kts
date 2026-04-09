plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "works.relux.vless_tun_app.platform.singbox"
    compileSdk = 36

    defaultConfig {
        minSdk = 33
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
    api(project(":core:model"))
    api(project(":core:render"))
    api(project(":core:runtime-contract"))
    api(files("libs/libbox.aar"))
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit)
}
