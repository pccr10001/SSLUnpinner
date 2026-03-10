pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenLocal()
        google()
        mavenCentral()
    }
}

rootProject.name = "SSL Unpinner"
include(":app")
include(":api")
project(":api").projectDir = file("libxposed-api/api")

include(":checks")
project(":checks").projectDir = file("libxposed-api/checks")

include(":libxposed-compat")
project(":libxposed-compat").projectDir = file("libxposed-compat/libxposed-compat")
