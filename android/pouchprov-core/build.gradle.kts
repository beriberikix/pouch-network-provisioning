// Copyright (c) 2026 Jonathan Beri
// SPDX-License-Identifier: Apache-2.0

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    // On-device self-signed device-certificate generation (BC does the ASN.1
    // X.509 building; keygen/signing use the platform JCA).
    implementation(libs.bouncycastle.pkix)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.org.json)
}

tasks.test {
    // The golden vectors in the repo root are the single source of truth shared
    // with the Python CLI and the Zephyr device codec. Point the tests at them
    // rather than duplicating the fixtures into the module.
    systemProperty("pouchprov.vectors.dir", rootProject.projectDir.parentFile.resolve("tests/vectors").absolutePath)
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
