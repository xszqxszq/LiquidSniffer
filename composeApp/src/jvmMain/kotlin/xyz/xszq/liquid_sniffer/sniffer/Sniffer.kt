package xyz.xszq.liquid_sniffer.sniffer

import kotlinx.coroutines.*
import org.pcap4j.core.BpfProgram
import org.pcap4j.core.PacketListener
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.Packet
import xyz.xszq.liquid_sniffer.payload.CapturedPacket

class Sniffer {
    private val parser = Parser()
    private var running = false
    private var startTimestamp = 0L
    private var job: Job? = null
    fun networkInterfaces(): List<PcapNetworkInterface> {
        val devices = Pcaps.findAllDevs()
        val lower = devices.filter { device ->
            LOW_PRIORITY_DEVICES.any { keyword ->
                keyword in device.description
            }
        }
        val higher = devices.filter { it !in lower }
        return higher + lower
    }
    fun capture(
        device: PcapNetworkInterface,
        filter: String ?= null,
        callback: (Int, Packet) -> Unit
    ) {
        val handle = device.openLive(
            65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
            10
        )
        runCatching {
            filter ?.let {
                handle.setFilter(filter.trim(), BpfProgram.BpfCompileMode.OPTIMIZE)
            }
        }.onFailure {
            return
        }
        var counter = 0
        running = true
        startTimestamp = System.currentTimeMillis()

        runCatching {
            handle.loop(-1, PacketListener { packet ->
                if (!running) {
                    handle.breakLoop()
                    return@PacketListener
                }
                callback(counter, packet)
                counter += 1
            })
        }
        handle.close()
    }
    @OptIn(DelicateCoroutinesApi::class)
    fun start(
        device: PcapNetworkInterface,
        wait: Boolean = false,
        filter: String ?= null,
        callback: (CapturedPacket<Packet>) -> Unit
    ) {
        job = GlobalScope.launch(Dispatchers.IO) {
            capture(device, filter) { id, packet ->
                val parsed = parser.parse(id, packet, startTimestamp) ?: return@capture
                callback(parsed)
            }
        }
        if (wait) {
            while (!stopped) {
                continue
            }
        }
    }
    fun stop() {
        running = false
        job ?.cancel()
    }
    val stopped: Boolean
        get() = job == null || !job!!.isActive

    companion object {
        val LOW_PRIORITY_DEVICES = listOf("VMware", "Bluetooth", "Virtual", "WAN Miniport")
    }
}