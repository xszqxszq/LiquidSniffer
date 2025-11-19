package xyz.xszq.liquid_sniffer.payload

import org.pcap4j.packet.Packet
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.DNS

data class ApplicationPacket(
    val type: ApplicationProtocol,
    val packet: Packet,
    val properties: List<Pair<String, String>>
) {
    companion object {
        fun Packet.parseDNS() = DNS?.let { dns ->
            ApplicationPacket(ApplicationProtocol.DNS, this, buildList {
                if (dns.header.isResponse) {
                    add("类型" to "回应")
                } else {
                    add("类型" to "询问")
                }
                add("应答" to (dns.header.getrCode()?.name() ?: "No Error"))
                add("回应" to dns.header.answers.toString())
                add("询问" to dns.header.questions.toString())
                add("权威" to dns.header.authorities.toString())
                add("附加信息" to dns.header.additionalInfo.toString())
            })
        }
        val ftpCommands = listOf(
            "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "AVBL", "CCC", "CDUP", "CONF", "CSID", "CWD",
            "DELE", "DSIZ", "ENC", "EPRT", "EPSV", "FEAT", "HELP", "HOST", "LANG", "LIST", "LPRT", "LPSV"
            , "MDTM", "MFCT", "MFF", "MFMT", "MIC", "MKD", "MLSD", "MLST", "MODE", "NLST", "NOOP", "OPTS",
            "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "REIN", "REST", "RETR", "RMD", "RMDA",
            "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "SPSV", "STAT", "STOR", "STOU", "STRU", "SYST", "THMB",
            "TYPE", "USER", "XCUP", "XMKD", "XPWD", "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN"
        )
        fun Packet.parseFTP(): ApplicationPacket? = runCatching {
            val text = rawData.decodeToString()
            val code = text.take(3)
            if (code.length == 3 && code.toIntOrNull() != null) {
                return ApplicationPacket(ApplicationProtocol.FTP, this, buildList {
                    add("类型" to "响应")
                    add("代码" to code)
                    add("消息" to text.substringAfter(code).trim())
                })
            }
            val command = text.take(4)
            if (command !in ftpCommands)
                return@runCatching null
            return ApplicationPacket(ApplicationProtocol.FTP, this, buildList {
                add("类型" to "请求")
                add("命令" to command)
                val params = text.substringAfter(command).trim()
                if (params.isNotBlank()) {
                    add("参数" to params)
                }
            })
        }.getOrNull()
        val httpMethods = listOf(
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
        )
        fun Packet.parseHTTP() = runCatching {
            val text = rawData.decodeToString()
            val headers = text.substringBefore("\r\n\r\n")
                .split("\r\n")
                .filter { it.isNotBlank() }

            ApplicationPacket(ApplicationProtocol.HTTP, this, buildList {
                val params = headers.firstOrNull() ?.split(" ") ?: return@runCatching null
                when {
                    params.size != 3 -> {
                        return@runCatching null
                    }
                    params[0].startsWith("HTTP") -> {
                        val (version, statusCode, status) = params
                        add("类型" to "应答")
                        add("状态" to "$statusCode $status")
                        add("版本" to version)
                    }
                    else -> {
                        val (method, path, version) = params
                        if (method !in httpMethods)
                            return@runCatching null
                        add("类型" to "请求")
                        add("方法" to method)
                        add("路径" to path)
                        add("版本" to version)
                    }
                }
                headers.takeLast(headers.size - 1).forEach { header ->
                    val (key, value) = header.split(":", limit = 2).map { it.trim() }
                    add(key to value)
                }
            })
        }.getOrNull()

        enum class TLSContentType(val value: Int) {
            Handshake(0x16),
            Alert(0x15),
            ChangeCipherSpec(0x14),
            ApplicationData(0x17);

            companion object {
                operator fun get(value: Int) = entries.firstOrNull { it.value == value }
            }
        }
        enum class TLSHandshakeType(val value: Int) {
            ClientHello(0x01),
            ServerHello(0x02);

            companion object {
                operator fun get(value: Int) = TLSHandshakeType.entries.firstOrNull { it.value == value }
            }
        }
        fun Packet.parseHTTPS(): ApplicationPacket? = runCatching {
            val properties = mutableListOf<Pair<String, String>>()

            val data = rawData
            if (data.size < 5)
                return@runCatching null

            fun unsignedByte(index: Int) =
                data[index].toUByte().toInt()
            fun unsignedShort(index: Int) =
                data[index].toUByte().toInt() * 256 + data[index + 1].toUByte().toInt()

            val contentType = TLSContentType[unsignedByte(0)] ?: return@runCatching null

            val length = unsignedShort(3)
            val version = when (val raw = unsignedShort(1)) {
                0x0301 -> "TLS 1.0"
                0x0302 -> "TLS 1.1"
                0x0303 -> "TLS 1.2"
                0x0304 -> "TLS 1.3/DTLS1.3"
                else -> "0x%04X".format(raw)
            }

            if (contentType == TLSContentType.Handshake) {
                TLSHandshakeType[unsignedByte(5)] ?.let {
                    properties.add("类型" to it.name)
                } ?: run {
                    properties.add("类型" to "Handshake(0x%02X)".format(unsignedByte(5)))
                }

            } else {
                properties.add("类型" to contentType.name)
            }
            properties.add("版本" to version)
            properties.add("长度" to length.toString())

            ApplicationPacket(ApplicationProtocol.HTTPS, this, properties)
        }.getOrNull()

    }
}
