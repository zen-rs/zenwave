plugins {
    id("com.android.application")
}

// Module repositories replace the ones in settings, so the public ones are repeated here.
repositories {
    google()
    mavenCentral()
}

android {
    namespace = "cool.lexo.zenwave.androidtest"
    compileSdk = 35

    defaultConfig {
        applicationId = "cool.lexo.zenwave.androidtest"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
}

// The Rust half: a cdylib built by cargo-ndk into jniLibs before every build.
val cargoBuild by tasks.registering(Exec::class) {
    description = "Builds the zenwave test cdylib for arm64-v8a with cargo-ndk"
    workingDir = file("../rust")
    commandLine(
        "cargo", "ndk",
        "--target", "arm64-v8a",
        "--platform", "28",
        "--output-dir", layout.projectDirectory.dir("src/main/jniLibs").asFile.path,
        "build",
    )
    outputs.upToDateWhen { false }
}

tasks.named("preBuild") {
    dependsOn(cargoBuild)
}

dependencies {

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("junit:junit:4.13.2")
}
