// SPDX-License-Identifier: Apache-2.0
plugins {
    kotlin("jvm")
    application
}
dependencies {
    implementation(project(":ares-client"))
    implementation(project(":ares-client-fhe"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    testImplementation(kotlin("test"))
}
application {
    mainClass.set("ares.smoke.MainKt")
}
kotlin { jvmToolchain(17) }
tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest { attributes["Main-Class"] = "ares.smoke.MainKt" }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    })
    // Exclude JAR signature files that cause SecurityException when merging
    // signed jars (e.g. BouncyCastle) into a single fat jar.
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")
}
