plugins {
    // Resolves Java toolchains (the modules pin jvmToolchain(17)) by auto-downloading
    // a JDK 17 when one isn't installed locally. Without this, on a host whose default
    // JDK is too new for the bundled Kotlin compiler (e.g. JDK 26), compilation falls
    // back to the daemon JVM and crashes (IllegalArgumentException parsing the version).
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "ares-kotlin-client"
include("ares-client", "ares-smoke", "ares-client-fhe")
