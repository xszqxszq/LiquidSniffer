package xyz.xszq.liquid_sniffer

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.jetbrains.compose.ui.tooling.preview.Preview
import org.pcap4j.packet.Packet
import xyz.xszq.liquid_sniffer.payload.CapturedPacket
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ARP
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ETH
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ICMP4
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.ICMP6
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.IPV4
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.IPV6
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.TCP
import xyz.xszq.liquid_sniffer.payload.CapturedPacket.Companion.UDP
import xyz.xszq.liquid_sniffer.sniffer.Sniffer

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Preview
fun App() {
    val sniffer = remember { Sniffer() }
    val devices = remember { sniffer.networkInterfaces().map { Pair(it.description, it) } }

    val packets = remember { mutableStateListOf<CapturedPacket<Packet>>() }

    var selectedDevice by remember { mutableStateOf<Int?>(null) }
    var selectedPacket by remember { mutableStateOf<Int?>(null) }
    var filter by remember { mutableStateOf(TextFieldValue(" ")) }

    val listState = rememberLazyListState()
    val scrollState = rememberScrollState()
    var running by remember { mutableStateOf(false) }
    var scrolling by remember { mutableStateOf(true) }

    val options: @Composable (() -> Unit) = {
        var expanded by remember { mutableStateOf(false) }
        val display = selectedDevice ?.let { it -> devices[it].first } ?: "请选择……"
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { if (!running) expanded = !expanded }
        ) {
            OutlinedTextField(
                value = display,
                onValueChange = {},
                readOnly = true,
                enabled = !running,
                label = { Text("网络适配器") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                    .width(360.dp),
                singleLine = true,
                textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
            )

            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                devices.forEachIndexed { index, (name, _) ->
                    DropdownMenuItem(
                        text = { Text(name, fontSize = 14.sp) },
                        onClick = {
                            selectedDevice = index
                            expanded = false
                        }
                    )
                }
            }
        }
        Spacer(modifier = Modifier.width(16.dp))
        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            label = { Text("捕获前过滤") },
            modifier = Modifier.width(360.dp),
            enabled = !running,
            singleLine = true,
            textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
        )
        Spacer(modifier = Modifier.width(16.dp))
        Button(
            onClick = {
                if (!running) {
                    selectedDevice ?.let {
                        packets.clear()
                        running = true

                        selectedPacket = null
                        scrolling = true

                        val device = devices[it].second
                        sniffer.start(device, filter = filter.text.takeIf { text -> text.isNotBlank() }) { packet ->
                            packets.add(packet)
                        }
                    }
                } else {
                    sniffer.stop()
                    running = false
                }
            }
        ) {
            Text(if (!running) "开始捕获" else "停止捕获")
        }
    }

    val packetList: @Composable RowScope.() -> Unit = {
        Column(Modifier.weight(0.5f).fillMaxHeight()) {
            Row(modifier = Modifier.fillMaxWidth()) {
                Text("序号", modifier = Modifier.width(50.dp))
                Text("时间", modifier = Modifier.width(120.dp))
                Text("源地址", modifier = Modifier.width(140.dp))
                Text("目标地址", modifier = Modifier.width(140.dp))
                Text("协议", modifier = Modifier.width(60.dp))
                Text("长度", modifier = Modifier.width(60.dp))
            }
            HorizontalDivider(Modifier.padding(vertical = 6.dp), DividerDefaults.Thickness,
                DividerDefaults.color)

            Box(modifier = Modifier.fillMaxSize()) {
                Box(modifier = Modifier.fillMaxSize().horizontalScroll(scrollState)) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        state = listState,
                        contentPadding = PaddingValues(bottom = 4.dp)
                    ) {
                        items(
                            count = packets.size,
                            key = { index -> packets[index].id }
                        ) { index ->
                            val packet = packets[index]
                            val isSelected = selectedPacket == packet.id
                            Row(
                                modifier = Modifier.fillMaxWidth()
                                    .background(
                                        if (isSelected)
                                            MaterialTheme.colorScheme.secondary.copy(alpha = 0.2f)
                                        else
                                            MaterialTheme.colorScheme.background
                                    )
                                    .clickable {
                                        selectedPacket = packet.id
                                        scrolling = false
                                    }
                                    .padding(vertical = 2.dp)
                            ) {
                                Text("${packet.id}", modifier = Modifier.width(50.dp))
                                Text("%.3f".format(packet.timestamp / 1000.0),
                                    modifier = Modifier.width(120.dp))
                                Text(packet.source.hostAddress, modifier = Modifier.width(140.dp))
                                Text(packet.destination.hostAddress, modifier = Modifier.width(140.dp))
                                Text(packet.protocol.toString(), modifier = Modifier.width(60.dp))
                                Text(packet.length.toString(), modifier = Modifier.width(60.dp))
                            }
                        }
                    }
                }
                VerticalScrollbar(
                    adapter = rememberScrollbarAdapter(listState),
                    modifier = Modifier
                        .align(Alignment.CenterEnd)
                        .fillMaxHeight()
                )
                HorizontalScrollbar(
                    adapter = rememberScrollbarAdapter(scrollState),
                    modifier = Modifier
                        .align(Alignment.BottomStart)
                        .fillMaxWidth()
                )
            }
        }
    }
    val detailed: @Composable RowScope.() -> Unit = {
        val selected = remember(selectedPacket, packets.size) {
            packets.firstOrNull { it.id == selectedPacket }
        }
        Column(
            modifier = Modifier.weight(0.5f).fillMaxHeight().padding(start = 4.dp)
        ) {
            Text("详细信息", style = MaterialTheme.typography.titleMedium)
            HorizontalDivider(Modifier.padding(vertical = 6.dp), DividerDefaults.Thickness,
                DividerDefaults.color)
            if (selected != null) {
                detailed(selected)
            } else {
                Text("", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            Column(Modifier.fillMaxSize()) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    options()
                }
                Spacer(Modifier.height(24.dp))
                Row(Modifier.fillMaxSize()) {
                    packetList()
                    VerticalDivider(Modifier.padding(horizontal = 12.dp), 0.5.dp,
                        DividerDefaults.color)
                    detailed()
                }
            }
        }
    }

    var programmatic by remember { mutableStateOf(false) }
    val isBottom by remember {
        derivedStateOf {
            val layout = listState.layoutInfo
            val total = layout.totalItemsCount
            if (total == 0) true
            else {
                val lastVisible = layout.visibleItemsInfo.lastOrNull() ?.index ?: 0
                lastVisible >= total - 3
            }
        }
    }

    LaunchedEffect(listState) {
        snapshotFlow {
            listState.firstVisibleItemIndex to listState.firstVisibleItemScrollOffset
        }.collect {
            if (!programmatic) {
                scrolling = isBottom
            }
        }
    }
    LaunchedEffect(packets.size) {
        if (scrolling && packets.isNotEmpty()) {
            programmatic = true
            try {
                listState.scrollToItem(packets.lastIndex)
            } finally {
                programmatic = false
            }
        }
    }

}

@Composable
private fun ExpandableSection(
    title: String,
    initiallyExpanded: Boolean = true,
    content: @Composable ColumnScope.() -> Unit
) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }
    ElevatedCard(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    ) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }
            ) {
                Text(if (expanded) "▼" else "▶", modifier = Modifier.width(20.dp))
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            AnimatedVisibility(visible = expanded) {
                Column(Modifier.fillMaxWidth().padding(top = 8.dp), content = content)
            }
        }
    }
}

fun hex(value: Short) = "0x"+"%04X".format(value.toInt() and 0xFFFF)

@Composable
fun detailed(captured: CapturedPacket<Packet>) {
    val packet = captured.packet

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        ExpandableSection("基本信息") {
            Text("编号：${captured.id}")
            Text("时间：${"%.3f".format(captured.timestamp / 1000.0)}")
            Text("长度：${captured.length}")
        }
        packet.ETH ?.let {
            ExpandableSection("以太帧") {
                Text("目标MAC：${it.header.dstAddr.toString().uppercase()}")
                Text("源MAC：${it.header.srcAddr.toString().uppercase()}")
                Text("类型：${hex(it.header.type.value())}")
            }
        }
        packet.IPV4 ?.let {
            ExpandableSection("IPv4") {
                Text("版本：${it.header.version}")
                Text("长度：${it.header.totalLengthAsInt}")
                Text("标识：${it.header.identificationAsInt}")
                Text(buildString {
                    append("标志：")
                    val flags = buildList {
                        if (it.header.moreFragmentFlag)
                            add("MF")
                        if (it.header.dontFragmentFlag)
                            add("DF")
                        if (it.header.fragmentOffset != 0.toShort())
                            add("offset=${it.header.fragmentOffset}")
                    }
                    append(flags.joinToString(", ").ifBlank { "无" })
                })
                Text("TTL：${it.header.ttlAsInt}")
                Text("协议：${it.header.protocol}")
                Text("校验：${hex(it.header.headerChecksum)}")
                Text("源地址：${it.header.srcAddr.hostAddress}")
                Text("目标地址：${it.header.dstAddr.hostAddress}")
            }
        }

        packet.IPV6?.let {
            ExpandableSection("IPv6") {
                Text("版本：${it.header.version}")
                Text("流量类型：${it.header.trafficClass}")
                Text("流标签：${it.header.flowLabel}")
                Text("长度：${it.header.payloadLengthAsInt}")
                Text("下一报头：${it.header.nextHeader}")
                Text("跃点限制：${it.header.hopLimitAsInt}")
                Text("源地址：${it.header.srcAddr.hostAddress}")
                Text("目标地址：${it.header.dstAddr.hostAddress}")
            }
        }

        packet.TCP ?.let {
            ExpandableSection("TCP") {
                Text("源端口：${it.header.srcPort.valueAsInt()}")
                Text("目标端口：${it.header.dstPort.valueAsInt()}")
                Text("序列号：${it.header.sequenceNumberAsLong}")
                Text("ACK：${it.header.acknowledgmentNumberAsLong}")
                Text("偏移：${it.header.dataOffset}")
                Text(buildString {
                    append("标志：")
                    val flags = buildList {
                        if (it.header.syn)
                            add("SYN")
                        if (it.header.ack)
                            add("ACK")
                        if (it.header.fin)
                            add("FIN")
                        if (it.header.rst)
                            add("RST")
                        if (it.header.psh)
                            add("PSH")
                        if (it.header.urg)
                            add("URG")
                    }
                    append(flags.joinToString(", ").ifBlank { "无" })
                })
                Text("窗口：${it.header.windowAsInt}")
                Text("校验：${hex(it.header.checksum)}")
                Text("紧急指针：${it.header.urgentPointer}")
            }
        }

        packet.UDP ?.let {
            ExpandableSection("UDP") {
                Text("源端口：${it.header.srcPort.valueAsInt()}")
                Text("目标端口：${it.header.dstPort.valueAsInt()}")
                Text("长度：${it.header.lengthAsInt}")
                Text("校验：${hex(it.header.checksum)}")
            }
        }

        packet.ICMP4 ?.let {
            ExpandableSection("ICMPv4") {
                Text("类型：${it.header.type}")
                Text("代码：${it.header.code}")
                Text("校验：${hex(it.header.checksum)}")
            }
        }
        packet.ICMP6 ?.let {
            ExpandableSection("ICMPv6") {
                Text("类型：${it.header.type}")
                Text("代码：${it.header.code}")
                Text("校验：${hex(it.header.checksum)}")
            }
        }
        packet.ARP ?.let {
            ExpandableSection("ARP") {
                Text("硬件类型：${it.header.hardwareType}")
                Text("协议类型：${it.header.protocolType}")
                Text("操作类型：${it.header.operation}")
                Text("源硬件地址：${it.header.srcHardwareAddr}")
                Text("源协议地址：${it.header.srcProtocolAddr.hostAddress}")
                Text("目标硬件地址：${it.header.dstHardwareAddr}")
                Text("目标协议地址：${it.header.dstProtocolAddr.hostAddress}")
            }
        }
        captured.payload ?.let { application ->
            ExpandableSection("应用层信息") {
                Text("应用层协议：${application.type}")
                application.properties.forEach { (key, value) ->
                    Text("$key：$value")
                }
            }
        }

        ExpandableSection("原始数据") {
            val dump = remember(packet.rawData) { captured.dump() }
            Box(
                Modifier.fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .horizontalScroll(rememberScrollState())
            ) {
                Text(
                    dump,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    modifier = Modifier.padding(8.dp)
                )
            }
        }
    }
}