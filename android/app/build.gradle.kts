import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Load local developer overrides from local.properties (gitignored).
// Developers set LIBERTY_DEBUG_PSK_HEX=<64-hex-char PSK> in local.properties
// to enable authenticated Hello frames in debug builds. Never commit a real PSK.
val localProps = Properties()
val localPropsFile = rootProject.file("local.properties")
if (localPropsFile.exists()) {
    localPropsFile.inputStream().use { localProps.load(it) }
}

android {
    namespace = "com.libertyshield.agent"
    compileSdk = 34
    ndkVersion = "26.1.10909125"
    defaultConfig {
        applicationId = "com.libertyshield.agent"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
        buildConfigField("String", "GATEWAY_URL", "\"http://192.168.68.107:8080/sensor/event\"")
        // DEBUG_PSK_HEX is intentionally absent from defaultConfig.
        // It is set per build type below to prevent accidental embedding in release APKs.
    }
    buildTypes {
        debug {
            // Load PSK from local.properties (gitignored). Empty = no Hello sent.
            buildConfigField(
                "String",
                "DEBUG_PSK_HEX",
                "\"${localProps.getProperty("LIBERTY_DEBUG_PSK_HEX", "")}\"",
            )
        }
        release {
            // Release builds must never embed a debug PSK, regardless of local.properties.
            buildConfigField("String", "DEBUG_PSK_HEX", "\"\"")
        }
    }
    buildFeatures {
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = "1.8" }
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.core:core-ktx:1.12.0")
    testImplementation("junit:junit:4.13.2")
}
