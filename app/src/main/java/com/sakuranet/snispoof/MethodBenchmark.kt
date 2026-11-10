package com.sakuranet.snispoof

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException

enum class BenchmarkOutcome {
    SUCCESS,
    DPI_RST,
    DPI_TIMEOUT,
    TCP_FAIL
}

data class MethodCandidate(
    val method: String,
    val strategy: String,
    val byteRange: String,
    val title: String,
    val rationale: String,
    val recommendedFor: String
)

data class BenchmarkItemState(
    val candidate: MethodCandidate,
    val isTesting: Boolean = false,
    val tested: Boolean = false,
    val outcome: BenchmarkOutcome? = null,
    val latencyMs: Long = 0,
    val statusDetail: String = ""
)

object BenchmarkEngine {

    val CANDIDATES = listOf(
        MethodCandidate(
            method = "combined",
            strategy = "sni_ext_boundary",
            byteRange = "1-5, 8-24, 32-64",
            title = "Combined (Boundary Slice + Decoy)",
            rationale = "Low-TTL decoy packet blinds DPI state machine, then SNI boundary is micro-sliced.",
            recommendedFor = "Restrictive Mobile Networks (Highest Bypass Rate)"
        ),
        MethodCandidate(
            method = "tls_record",
            strategy = "sni_split",
            byteRange = "1-12, 13-36, 40-80",
            title = "TLS Record Layer Slicing",
            rationale = "Splits ClientHello into multiple genuine TLS records; avoids TCP-level DPI triggers.",
            recommendedFor = "Middleboxes sensitive to TCP fragmentation & Datacenter CDNs"
        ),
        MethodCandidate(
            method = "fragment",
            strategy = "byte_range",
            byteRange = "1-5, 8-24, 32-64",
            title = "Micro Byte-Range Fragmentation",
            rationale = "TCP segments carved at precise byte intervals with dynamic 5-15ms delays.",
            recommendedFor = "Fixed Broadband & Shallow Buffer Firewalls"
        ),
        MethodCandidate(
            method = "disorder",
            strategy = "sni_ext_boundary",
            byteRange = "1-5, 8-24, 32-64",
            title = "TTL Disorder Desync",
            rationale = "Multi-record TLS framing plus jittered TCP segments cut at the SNI extension boundary.",
            recommendedFor = "Hardware DPI Appliances (Huawei, Sandvine, Fortinet)"
        ),
        MethodCandidate(
            method = "oob",
            strategy = "sni_split",
            byteRange = "1-5, 8-24, 32-64",
            title = "Out-Of-Band (TCP URG) Decoy",
            rationale = "Injects 1-byte urgent payload that target server ignores but confuses DPI parsers.",
            recommendedFor = "Older DPI Appliances & Gateway Middleboxes"
        ),
        MethodCandidate(
            method = "fragment",
            strategy = "sni_split",
            byteRange = "1-5, 8-24, 32-64",
            title = "Center SNI Midpoint Split",
            rationale = "Cuts exactly at the middle character of the SNI domain string.",
            recommendedFor = "Simple Keyword Matching Firewalls"
        ),
        MethodCandidate(
            method = "inject",
            strategy = "sni_ext_boundary",
            byteRange = "1-5, 8-24, 32-64",
            title = "Unmodified ClientHello (Baseline)",
            rationale = "The real ClientHello sent in one piece (the proxy adds a decoy first). If this passes, the SNI is not being blocked on this path.",
            recommendedFor = "Baseline check for the other results"
        )
    )

    /**
     * Sends a ClientHello for [testSni] to [targetIp] using exactly the bytes and segmentation the
     * proxy would use for [candidate] (via [ClientHelloSender]), then classifies the reply.
     *
     * [testSni] must be a domain the DPI actually blocks (e.g. the real SNI of your v2ray server);
     * with a clean SNI every method passes and the results say nothing. Decoys are not sent here:
     * they travel on separate connections and cannot change what happens on the probed one.
     */
    suspend fun probeMethod(
        context: Context,
        targetIp: String,
        targetPort: Int,
        testSni: String,
        fakeSni: String,
        candidate: MethodCandidate
    ): Pair<BenchmarkOutcome, Pair<Long, String>> = withContext(Dispatchers.IO) {
        val startNs = System.nanoTime()
        var socket: Socket? = null
        try {
            val s = Socket()
            socket = s
            s.tcpNoDelay = true
            s.soTimeout = 4000

            // Bind to physical non-VPN network to ensure accurate testing
            NetworkTools.bindSocketToPhysicalNetwork(context, s)
            s.connect(InetSocketAddress(targetIp, targetPort), 4500)

            val out: OutputStream = s.getOutputStream()
            val input: InputStream = s.getInputStream()

            val clientHello = TlsClientHelloManipulator.buildSyntheticClientHello(testSni)
            val probeConfig = SpoofConfig(
                connectIp = targetIp,
                connectPort = targetPort,
                fakeSni = fakeSni,
                method = candidate.method,
                fragmentStrategy = candidate.strategy,
                byteRangeSpec = candidate.byteRange
            )
            ClientHelloSender.send(
                upstreamSocket = s,
                upstreamOut = out,
                firstPacket = clientHello,
                config = probeConfig,
                sendDecoyClientHello = { }
            )

            // Read response
            val buf = ByteArray(1024)
            val readLen = input.read(buf)
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
            val contentType = if (readLen > 0) buf[0].toInt() and 0xFF else -1

            when {
                readLen <= 0 ->
                    Pair(BenchmarkOutcome.DPI_RST, Pair(elapsedMs, "Connection closed before any reply (likely DPI)"))
                contentType == 0x16 && (readLen < 6 || buf[5].toInt() == 0x02) ->
                    Pair(BenchmarkOutcome.SUCCESS, Pair(elapsedMs, "TLS ServerHello received ($readLen bytes)"))
                contentType == 0x15 ->
                    Pair(
                        BenchmarkOutcome.SUCCESS,
                        Pair(elapsedMs, "TLS alert from server: DPI let it through, the server rejected the test hello")
                    )
                else ->
                    Pair(BenchmarkOutcome.TCP_FAIL, Pair(elapsedMs, "Unexpected non-TLS reply ($readLen bytes, possible block page)"))
            }
        } catch (e: SocketTimeoutException) {
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
            Pair(BenchmarkOutcome.DPI_TIMEOUT, Pair(elapsedMs, "Packets dropped or timed out by DPI filter (Timeout)"))
        } catch (e: SocketException) {
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
            val msg = e.message.orEmpty().lowercase()
            if (msg.contains("reset") || msg.contains("abort") || msg.contains("broken pipe")) {
                Pair(BenchmarkOutcome.DPI_RST, Pair(elapsedMs, "TCP RST injected by DPI middlebox (Connection Reset)"))
            } else {
                Pair(BenchmarkOutcome.TCP_FAIL, Pair(elapsedMs, "Socket error: ${e.message}"))
            }
        } catch (e: Exception) {
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
            Pair(BenchmarkOutcome.TCP_FAIL, Pair(elapsedMs, "Connection failure: ${e.message}"))
        } finally {
            runCatching { socket?.close() }
        }
    }

}

@Composable
fun MethodBenchmarkScreen(
    context: Context,
    targetIp: String,
    targetPort: Int,
    fakeSni: String,
    currentMethod: String,
    currentStrategy: String,
    onApplyMethod: (method: String, strategy: String, byteRange: String) -> Unit,
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    var isRunningAll by remember { mutableStateOf(false) }
    var currentTestingIndex by remember { mutableIntStateOf(-1) }
    // A domain the DPI actually blocks (normally the real SNI of the v2ray server). Testing with
    // the clean Fake SNI would make every method "pass".
    var blockedSni by remember { mutableStateOf("") }
    val testSni = blockedSni.trim().ifBlank { fakeSni.trim() }

    var states by remember {
        mutableStateOf(
            BenchmarkEngine.CANDIDATES.map { BenchmarkItemState(candidate = it) }
        )
    }

    val bestCandidate = remember(states) {
        states.filter { it.outcome == BenchmarkOutcome.SUCCESS }
            .minByOrNull { it.latencyMs }
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("method_benchmark_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Benchmark Header Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.3f))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Automated Method Benchmark & Diagnostics",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Test bypass techniques against your target edge ($targetIp:$targetPort)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Test SNI: ${testSni.ifBlank { "Not set" }}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Active: $currentMethod ($currentStrategy)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                OutlinedTextField(
                    value = blockedSni,
                    onValueChange = { blockedSni = it },
                    label = { Text("Blocked SNI to test (your real server SNI)") },
                    singleLine = true,
                    enabled = !isRunningAll,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("benchmark_blocked_sni_input")
                )
                Text(
                    text = if (blockedSni.isBlank()) {
                        "No blocked SNI set: testing with the clean Fake SNI, so every method will probably pass and the results won't tell the methods apart."
                    } else {
                        "Each method sends a ClientHello for this SNI exactly as the proxy would. Decoys are not sent during the test."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (blockedSni.isBlank()) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                )

                Button(
                    enabled = !isRunningAll && targetIp.isNotBlank() && testSni.isNotBlank(),
                    onClick = {
                        scope.launch {
                            isRunningAll = true
                            val updated = states.toMutableList()
                            for (i in updated.indices) {
                                currentTestingIndex = i
                                updated[i] = updated[i].copy(isTesting = true)
                                states = updated.toList()

                                val (outcome, res) = BenchmarkEngine.probeMethod(
                                    context = context,
                                    targetIp = targetIp.trim(),
                                    targetPort = targetPort,
                                    testSni = testSni,
                                    fakeSni = fakeSni.trim(),
                                    candidate = updated[i].candidate
                                )

                                updated[i] = updated[i].copy(
                                    isTesting = false,
                                    tested = true,
                                    outcome = outcome,
                                    latencyMs = res.first,
                                    statusDetail = res.second
                                )
                                states = updated.toList()
                            }
                            currentTestingIndex = -1
                            isRunningAll = false
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag("run_benchmark_button")
                ) {
                    if (isRunningAll) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("Testing method ${(currentTestingIndex + 1)} of ${states.size}...")
                    } else {
                        Text(
                            text = "Run Automated Method Benchmark",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        // Winning Recommendation Card
        AnimatedVisibility(visible = bestCandidate != null) {
            bestCandidate?.let { best ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFE8F5E9)),
                    border = BorderStroke(1.5.dp, Color(0xFF2E7D32))
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "🏆 Top Recommended Method from Benchmark",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1B5E20)
                            )
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = Color(0xFF2E7D32)
                            ) {
                                Text(
                                    text = "Latency: ${best.latencyMs} ms",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        }
                        Text(
                            text = best.candidate.title,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFF1B5E20)
                        )
                        Text(
                            text = best.candidate.rationale,
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF2E7D32)
                        )
                        Button(
                            onClick = {
                                onApplyMethod(
                                    best.candidate.method,
                                    best.candidate.strategy,
                                    best.candidate.byteRange
                                )
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32)),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 44.dp)
                                .testTag("apply_best_method_button")
                        ) {
                            Text("Apply This Method to Proxy")
                        }
                    }
                }
            }
        }

        Text(
            text = "Tested Methods & Diagnostics:",
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.Bold
        )

        // List of candidate cards
        for (item in states) {
            BenchmarkItemCard(
                item = item,
                isCurrent = item.candidate.method == currentMethod && item.candidate.strategy == currentStrategy,
                onApply = {
                    onApplyMethod(
                        item.candidate.method,
                        item.candidate.strategy,
                        item.candidate.byteRange
                    )
                }
            )
        }
    }
}

@Composable
fun BenchmarkItemCard(
    item: BenchmarkItemState,
    isCurrent: Boolean,
    onApply: () -> Unit
) {
    val borderColor = when (item.outcome) {
        BenchmarkOutcome.SUCCESS -> Color(0xFF2E7D32)
        BenchmarkOutcome.DPI_RST -> Color(0xFFC62828)
        BenchmarkOutcome.DPI_TIMEOUT -> Color(0xFFE65100)
        BenchmarkOutcome.TCP_FAIL -> Color(0xFFD32F2F)
        null -> MaterialTheme.colorScheme.outlineVariant
    }

    val containerColor = when (item.outcome) {
        BenchmarkOutcome.SUCCESS -> Color(0xFFF1F8E9)
        BenchmarkOutcome.DPI_RST -> Color(0xFFFFEBEE)
        BenchmarkOutcome.DPI_TIMEOUT -> Color(0xFFFFF3E0)
        BenchmarkOutcome.TCP_FAIL -> Color(0xFFFFEBEE)
        null -> MaterialTheme.colorScheme.surface
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("benchmark_card_${item.candidate.method}_${item.candidate.strategy}"),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.candidate.title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Method: ${item.candidate.method} • Strategy: ${item.candidate.strategy}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                when {
                    item.isTesting -> {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    }
                    item.outcome == BenchmarkOutcome.SUCCESS -> {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0xFF2E7D32)
                        ) {
                            Text(
                                text = "Pass • ${item.latencyMs} ms",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                    item.outcome == BenchmarkOutcome.DPI_RST -> {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0xFFC62828)
                        ) {
                            Text(
                                text = "Blocked (TCP RST)",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                    item.outcome == BenchmarkOutcome.DPI_TIMEOUT -> {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0xFFE65100)
                        ) {
                            Text(
                                text = "Dropped (Timeout)",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                    item.outcome == BenchmarkOutcome.TCP_FAIL -> {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0xFFD32F2F)
                        ) {
                            Text(
                                text = "Socket Error",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                    else -> {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            Text(
                                text = "Untested",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }

            Text(
                text = item.candidate.rationale,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Text(
                text = "Best for: ${item.candidate.recommendedFor}",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.primary
            )

            if (item.tested && item.statusDetail.isNotBlank()) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = Color.Black.copy(alpha = 0.05f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = item.statusDetail,
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(6.dp)
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isCurrent) {
                    Text(
                        text = "✓ Currently active in settings",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else {
                    Spacer(Modifier.width(1.dp))
                }

                OutlinedButton(
                    onClick = onApply,
                    modifier = Modifier
                        .heightIn(min = 36.dp)
                        .testTag("apply_candidate_${item.candidate.method}")
                ) {
                    Text(
                        text = if (isCurrent) "Re-Apply" else "Apply Method",
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
        }
    }
}
