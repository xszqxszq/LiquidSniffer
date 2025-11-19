package xyz.xszq.liquid_sniffer.sniffer

import org.pcap4j.packet.Packet
import org.pcap4j.packet.namednumber.IpNumber
import xyz.xszq.liquid_sniffer.payload.ApplicationPacket
import xyz.xszq.liquid_sniffer.payload.ApplicationPacket.Companion.parseDNS
import xyz.xszq.liquid_sniffer.payload.ApplicationPacket.Companion.parseFTP
import xyz.xszq.liquid_sniffer.payload.ApplicationPacket.Companion.parseHTTP
import xyz.xszq.liquid_sniffer.payload.ApplicationPacket.Companion.parseHTTPS
import xyz.xszq.liquid_sniffer.payload.CapturedPacket
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ARP
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ICMP4
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ICMP6
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.IPV4
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.IPV6
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.TCP
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.UDP
import xyz.xszq.liquid_sniffer.payload.Protocol
import java.net.InetAddress

class Parser {
    private fun <T: Packet> parseInternal(
        id: Int,
        timestamp: Long,
        packet: T,
        sourceAddr: InetAddress,
        destAddr: InetAddress
    ): CapturedPacket<Packet>? {
        val ipv6 = packet.IPV6 != null
        packet.TCP ?.let { tcp ->
            return CapturedPacket(
                id, Protocol.TCP, sourceAddr, destAddr,
                timestamp, tcp.length(), packet, ipv6, application(tcp.payload)
            )
        }
        packet.UDP ?.let { udp ->
            return CapturedPacket(
                id, Protocol.UDP, sourceAddr, destAddr,
                timestamp, udp.length(), packet, ipv6, application(udp.payload)
            )
        }
        return null
    }
    fun parse(
        id: Int,
        packet: Packet,
        startTimestamp: Long
    ): CapturedPacket<Packet>? {
        val timestamp = System.currentTimeMillis() - startTimestamp
        packet.ARP ?.let { arp ->
            return CapturedPacket(
                id, Protocol.ARP, arp.header.srcProtocolAddr, arp.header.dstProtocolAddr,
                timestamp, arp.length(), packet
            )
        }
        packet.IPV4 ?.let { ipv4 ->
            val sourceAddr = ipv4.header.srcAddr
            val destAddr = ipv4.header.dstAddr
            parseInternal(id, timestamp, packet, sourceAddr, destAddr) ?.let {
                return it
            }
            packet.ICMP4 ?.let { icmp ->
                return CapturedPacket(
                    id, Protocol.ICMP, sourceAddr, destAddr,
                    timestamp, icmp.length(), packet
                )
            }
            if (ipv4.header.protocol == IpNumber.IGMP) {
                val igmp = packet.payload
                return CapturedPacket(
                    id, Protocol.IGMP, sourceAddr, destAddr,
                    timestamp, igmp.length(), packet
                )
            }
        }
        packet.IPV6 ?.let { ipv6 ->
            val sourceAddr = ipv6.header.srcAddr
            val destAddr = ipv6.header.dstAddr
            parseInternal(id, timestamp, packet, sourceAddr, destAddr) ?.let {
                return it
            }
            packet.ICMP6 ?.let { icmp ->
                return CapturedPacket(
                    id, Protocol.ICMP, sourceAddr, destAddr,
                    timestamp, icmp.length(), packet, true
                )
            }
            if (ipv6.header.protocol == IpNumber.IGMP) {
                val igmp = packet.payload
                return CapturedPacket(
                    id, Protocol.IGMP, sourceAddr, destAddr,
                    timestamp, igmp.length(), packet
                )
            }
        }
        return null
    }
    fun application(
        packet: Packet
    ): ApplicationPacket? {
        packet.parseDNS() ?.let { dns ->
            return dns
        }
        packet.parseHTTP() ?.let { http ->
            return http
        }
        packet.parseHTTPS() ?.let { https ->
            return https
        }
        packet.parseFTP() ?.let { ftp ->
            return ftp
        }
        return null
    }
}