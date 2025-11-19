package xyz.xszq.liquid_sniffer.payload

import org.pcap4j.packet.*
import java.net.InetAddress

data class CapturedPacket<T: Packet>(
    val id: Int,
    val protocol: Protocol,
    val source: InetAddress,
    val destination: InetAddress,
    val timestamp: Long,
    val length: Int,
    val packet: T,
    val ipv6: Boolean = false,
    val payload: ApplicationPacket ?= null
) {
    companion object {
        val Packet.ETH: EthernetPacket?
            get() = get(EthernetPacket::class.java)
        val Packet.ARP: ArpPacket?
            get() = get(ArpPacket::class.java)
        val Packet.IPV4: IpV4Packet?
            get() = get(IpV4Packet::class.java)
        val Packet.IPV6: IpV6Packet?
            get() = get(IpV6Packet::class.java)
        val Packet.ICMP4: IcmpV4CommonPacket?
            get() = get(IcmpV4CommonPacket::class.java)
        val Packet.ICMP6: IcmpV6CommonPacket?
            get() = get(IcmpV6CommonPacket::class.java)
        val Packet.TCP: TcpPacket?
            get() = get(TcpPacket::class.java)
        val Packet.UDP: UdpPacket?
            get() = get(UdpPacket::class.java)

        val Packet.DNS: DnsPacket?
            get() = get(DnsPacket::class.java)
    }
    fun dump(
        bytesPerLine: Int = 16
    ) = buildString {
        var offset = 0
        while (offset < packet.rawData.size) {
            val line = packet.rawData
                .sliceArray(offset until minOf(offset + bytesPerLine, packet.rawData.size))
            append("%04X  ".format(offset))
            append(line.joinToString(" ") { "%02X".format(it) })
            append(" ".repeat((bytesPerLine - line.size).coerceAtLeast(0) * 3))
            append("  ")
            appendLine(line.map { b ->
                val c = Char(b.toInt() and 0xFF)
                if (c.isISOControl() || c.code !in 32..126)
                    '.'
                else
                    c
            }.joinToString(""))
            offset += bytesPerLine
        }
    }
}
