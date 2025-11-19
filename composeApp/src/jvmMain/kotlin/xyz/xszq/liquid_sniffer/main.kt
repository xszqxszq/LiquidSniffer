package xyz.xszq.liquid_sniffer

import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState


fun loadLibraries() {
    val path =  "C:/Windows/System32/Npcap"

    val prop = System.getProperty("jna.library.path") ?.let {
        "$it;$path"
    } ?: path
    System.setProperty("jna.library.path", prop)
}

fun main() {
    println(System.getProperty("compose.application.resources.dir"))
    loadLibraries()
    application {
        val state = rememberWindowState(
            size = DpSize(1280.dp, 600.dp),
            position = WindowPosition(Alignment.Center)
        )
        Window(
            onCloseRequest = ::exitApplication,
            title = "LiquidSniffer - xszqxszq@UCAS",
            state = state,
        ) {
            App()
        }
    }
}