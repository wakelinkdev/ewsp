plugins {
    kotlin("jvm") version "1.9.22"
    kotlin("plugin.serialization") version "1.9.22"
    id("maven-publish")
}

group = "org.wakelink"
version = "3.0.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "org.wakelink"
            artifactId = "ewsp-core"
            version = "3.0.0"
            
            from(components["java"])
            
            pom {
                name.set("EWSP Core")
                description.set("WakeLink Protocol cryptographic library - Kotlin/JVM binding")
                url.set("https://github.com/deadboizxc/wakelink")
                
                licenses {
                    license {
                        name.set("NGC License v1.0")
                        url.set("https://github.com/deadboizxc/wakelink/blob/main/LICENSE")
                    }
                }
            }
        }
    }
}

java {
    withSourcesJar()
    withJavadocJar()
}
