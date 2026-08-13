// Aegis Android Companion — Gradle build file.
//
// The companion is a standard Android Gradle project. Build with:
//   ./gradlew assembleDebug
// Test with:
//   ./gradlew test
plugins {
    id("com.android.application")
    id("kotlin-android")
}

android {
    namespace = "com.guardianmesh.aegis"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.guardianmesh.aegis"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.8.0"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    testImplementation("junit:junit:4.13.2")
}
