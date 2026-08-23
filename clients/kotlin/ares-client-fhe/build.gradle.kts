plugins { kotlin("jvm") }
dependencies {
    implementation(project(":ares-client"))
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}
kotlin { jvmToolchain(17) }
tasks.test {
    useJUnitPlatform()
    // FHE tests use small, fast, sub-128-bit CKKS rings; the canonical bridge is
    // secure-by-default (HEStd_128_classic) and rejects them, so opt the test JVM
    // out. The bridge prints a one-time warning. NEVER set this in production.
    environment("ARES_FHE_ALLOW_INSECURE", "1")
    systemProperty("java.library.path",
        layout.buildDirectory.dir("native").get().asFile.absolutePath +
        File.pathSeparator + System.getProperty("java.library.path"))
}
