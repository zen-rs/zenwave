plugins {
    id("com.android.application")
}

/// The Kotlin half of rustls-platform-verifier ships as an `.aar` inside the
/// `rustls-platform-verifier-android` crate, located through `cargo metadata`
/// so its version follows the Rust dependency of the crate under `../rust`.
data class PlatformVerifierArtifact(val repository: File, val version: String)

fun platformVerifierArtifact(): PlatformVerifierArtifact {
    val metadata = providers.exec {
        workingDir = file("../rust")
        commandLine(
            "cargo", "metadata", "--format-version", "1",
            "--filter-platform", "aarch64-linux-android",
        )
    }.standardOutput.asText.get()
    @Suppress("UNCHECKED_CAST")
    val packages = (groovy.json.JsonSlurper().parseText(metadata) as Map<String, Any>)["packages"] as List<Map<String, Any>>
    val crate = packages.first { it["name"] == "rustls-platform-verifier-android" }
    val manifest = File(crate["manifest_path"] as String)
    return PlatformVerifierArtifact(File(manifest.parentFile, "maven"), crate["version"] as String)
}

val platformVerifier = platformVerifierArtifact()

// Module repositories replace the ones in settings, so the public ones are repeated here.
repositories {
    google()
    mavenCentral()
    maven {
        url = uri(platformVerifier.repository)
        metadataSources { artifact() }
    }
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
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
    // The Kotlin half of rustls-platform-verifier, from the crate's bundled Maven repository.
    implementation("rustls:rustls-platform-verifier:${platformVerifier.version}@aar")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("junit:junit:4.13.2")
}
