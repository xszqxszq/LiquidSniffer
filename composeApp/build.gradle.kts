import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.composeHotReload)
}

kotlin {
    jvm()
    
    sourceSets {
        commonMain.dependencies {
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation(compose.components.resources)
            implementation(compose.components.uiToolingPreview)
            implementation(libs.androidx.lifecycle.viewmodelCompose)
            implementation(libs.androidx.lifecycle.runtimeCompose)
            implementation("org.pcap4j:pcap4j-core:1.8.2")
            implementation("org.pcap4j:pcap4j-packetfactory-static:1.8.2")
            runtimeOnly("org.slf4j:slf4j-nop:2.0.16")
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        jvmMain.dependencies {
            implementation(compose.desktop.currentOs)
            implementation(libs.kotlinx.coroutinesSwing)
        }
    }
}


compose.desktop {
    application {
        mainClass = "xyz.xszq.liquid_sniffer.MainKt"

        nativeDistributions {
            targetFormats(TargetFormat.Exe)
            packageName = "xyz.xszq.liquid_sniffer"
            packageVersion = "1.0.0"
            modules("java.sql")
            windows {
                console = true
            }
        }
        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}