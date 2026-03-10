// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "8.12.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}

subprojects {
    afterEvaluate {
        if (name == "checks") {
            tasks.configureEach {
                if (name.contains("compile", ignoreCase = true) || name.contains("lint", ignoreCase = true)) {
                    enabled = false
                }
            }
        }
        if (name == "libxposed-compat" || name == "api") {
            plugins.withId("com.android.library") {
                val android = extensions.getByName("android") as com.android.build.gradle.LibraryExtension
                android.compileOptions {
                    sourceCompatibility = JavaVersion.VERSION_11
                    targetCompatibility = JavaVersion.VERSION_11
                }
            }
            tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
                kotlinOptions.jvmTarget = "11"
            }
            tasks.withType<JavaCompile>().configureEach {
                sourceCompatibility = "11"
                targetCompatibility = "11"
            }
        }
    }
}
