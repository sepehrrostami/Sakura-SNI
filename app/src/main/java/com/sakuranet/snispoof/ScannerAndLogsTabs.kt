package com.sakuranet.snispoof

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SniScannerTab(
    connectIp: String,
    connectPort: Int,
    listenPort: Int,
    currentFakeSni: String,
    onSelectSni: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var customDomainsText by remember {
        mutableStateOf(SpoofConfig.DEFAULT_CLEAN_SNIS.joinToString("\n"))
    }
    var isScanning by remember { mutableStateOf(false) }
    var scanResults by remember { mutableStateOf<List<SniProbeResult>>(emptyList()) }
    var completedCount by remember { mutableStateOf(0) }
    var totalCount by remember { mutableStateOf(0) }
    var localPortProbe by remember { mutableStateOf<TcpProbeResult?>(null) }
    var isTestingLocalPort by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("sni_scanner_tab"),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Live Clean-SNI TLS Handshake Scanner",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Probes real TLS ClientHello/ServerHello handshakes against ${connectIp.ifBlank { "<edge-ip>" }}:$connectPort over the physical network interface (bypassing active VPN tunnels) to find clean SNIs that pass DPI without reset.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = customDomainsText,
                    onValueChange = { customDomainsText = it },
                    label = { Text("Candidate SNI Domains (one per line)") },
                    minLines = 4,
                    maxLines = 6,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("scanner_domains_input")
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        enabled = !isScanning && connectIp.isNotBlank(),
                        modifier = Modifier
                            .weight(1.3f)
                            .heightIn(min = 48.dp)
                            .testTag("scan_sni_button"),
                        onClick = {
                            val domains = customDomainsText
                                .lines()
                                .map { it.trim() }
                                .filter { it.isNotBlank() }
                                .distinct()
                            if (domains.isNotEmpty()) {
                                isScanning = true
                                scanResults = emptyList()
                                completedCount = 0
                                totalCount = domains.size
                                scope.launch {
                                    val live = mutableListOf<SniProbeResult>()
                                    val finalSorted = NetworkTools.scanCandidateSnis(
                                        edgeIp = connectIp,
                                        edgePort = connectPort,
                                        domains = domains,
                                        timeoutMs = 3500,
                                        context = context,
                                        onProgress = { res ->
                                            synchronized(live) {
                                                live.add(res)
                                                completedCount = live.size
                                                scanResults = live.sortedWith(
                                                    compareByDescending<SniProbeResult> { it.success }
                                                        .thenBy { it.handshakeMs }
                                                )
                                            }
                                        }
                                    )
                                    scanResults = finalSorted
                                    isScanning = false
                                    LogBus.push(
                                        "[scanner] Probed ${finalSorted.size} SNIs on $connectIp:$connectPort — " +
                                            "${finalSorted.count { it.success }} passed TLS handshake"
                                    )
                                }
                            }
                        }
                    ) {
                        Text(
                            text = if (isScanning) {
                                "Scanning ($completedCount/$totalCount)…"
                            } else {
                                "Scan Clean SNIs"
                            },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    OutlinedButton(
                        enabled = !isTestingLocalPort,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("check_local_port_button"),
                        onClick = {
                            isTestingLocalPort = true
                            scope.launch {
                                localPortProbe = NetworkTools.testTcpLatency("127.0.0.1", listenPort, 1500, context)
                                isTestingLocalPort = false
                            }
                        }
                    ) {
                        Text(
                            text = if (isTestingLocalPort) "Checking…" else "Check :$listenPort",
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                if (isScanning && totalCount > 0) {
                    LinearProgressIndicator(
                        progress = { completedCount.toFloat() / totalCount.toFloat() },
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                localPortProbe?.let { probe ->
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = if (probe.reachable) {
                            Color(0xFFE7F6EE)
                        } else {
                            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.65f)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = if (probe.reachable) {
                                "Local proxy listener 127.0.0.1:${probe.port} is OPEN (${probe.rttMs}ms)"
                            } else {
                                "Local listener 127.0.0.1:${probe.port} not listening (${probe.detail})"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = if (probe.reachable) Color(0xFF0E4F30) else MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }
            }
        }

        if (scanResults.isNotEmpty()) {
            Text(
                text = "Scan Results (${scanResults.count { it.success }}/${scanResults.size} passed)",
                style = MaterialTheme.typography.labelLarge
            )
            scanResults.forEach { item ->
                val isSelected = item.sniDomain.equals(currentFakeSni, ignoreCase = true)
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    border = if (isSelected) {
                        BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary)
                    } else {
                        null
                    }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = if (item.success) Color(0xFF1B8755) else MaterialTheme.colorScheme.error
                                ) {
                                    Text(
                                        text = if (item.success) "${item.handshakeMs} ms" else "FAIL",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp)
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = item.sniDomain,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = item.detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        if (item.success) {
                            FilledTonalButton(
                                onClick = { onSelectSni(item.sniDomain) },
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text(if (isSelected) "Active" else "Use SNI")
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RealTimeLogDisplay(
    logLines: List<String>,
    isServiceRunning: Boolean,
    onClearLogs: () -> Unit,
    modifier: Modifier = Modifier,
    terminalHeight: androidx.compose.ui.unit.Dp = 240.dp
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf("ALL") }
    var autoScroll by remember { mutableStateOf(true) }
    val listState = rememberLazyListState()

    val filteredLogs = remember(logLines, searchQuery, selectedFilter) {
        logLines.filter { line ->
            val matchesLevel = when (selectedFilter) {
                "ERROR" -> line.contains("error", ignoreCase = true) || line.contains("fail", ignoreCase = true)
                "WARN" -> line.contains("warn", ignoreCase = true)
                "INFO" -> !line.contains("[error]", ignoreCase = true) && !line.contains("[warn]", ignoreCase = true)
                else -> true
            }
            val matchesQuery = searchQuery.isBlank() || line.contains(searchQuery.trim(), ignoreCase = true)
            matchesLevel && matchesQuery
        }
    }

    LaunchedEffect(filteredLogs.size, autoScroll) {
        if (autoScroll && filteredLogs.isNotEmpty()) {
            listState.animateScrollToItem(filteredLogs.size - 1)
        }
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag("realtime_log_display"),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = "Live Service Logs",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = if (isServiceRunning) Color(0xFF1B8755) else MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.testTag("log_stream_status_badge")
                    ) {
                        Text(
                            text = if (isServiceRunning) "LIVE" else "IDLE",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = if (isServiceRunning) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(
                        onClick = {
                            copyToClipboard(context, "sakura-sni-logs", filteredLogs.joinToString("\n"))
                        },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.testTag("copy_logs_button")
                    ) {
                        Text("Copy", style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = onClearLogs,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.testTag("clear_logs_button")
                    ) {
                        Text("Clear", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search / filter log stream") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("log_search_input")
            )

            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalArrangement = Arrangement.Center
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("ALL", "INFO", "WARN", "ERROR").forEach { level ->
                        FilterChip(
                            selected = selectedFilter == level,
                            onClick = { selectedFilter = level },
                            label = { Text(level, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = autoScroll,
                        onCheckedChange = { autoScroll = it },
                        modifier = Modifier.testTag("log_autoscroll_checkbox")
                    )
                    Text("Auto-scroll", style = MaterialTheme.typography.labelSmall)
                }
            }

            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(terminalHeight)
                    .testTag("log_stream_terminal"),
                shape = RoundedCornerShape(10.dp),
                color = Color(0xFF13161C),
                tonalElevation = 2.dp
            ) {
                if (filteredLogs.isEmpty()) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = if (logLines.isEmpty()) {
                                "Waiting for SNI spoofing service output… Tap 'Start Proxy' to stream live stdout/stderr logs."
                            } else {
                                "No log lines match the current filter ($selectedFilter)."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF8C96A8),
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(10.dp)
                            .testTag("log_stream_list"),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        items(filteredLogs) { line ->
                            val lineColor = when {
                                line.contains("[error]", ignoreCase = true) ||
                                    line.contains("failed", ignoreCase = true) -> Color(0xFFFF7B7B)
                                line.contains("[warn]", ignoreCase = true) -> Color(0xFFFFCF6E)
                                line.contains("[service]", ignoreCase = true) ||
                                    line.contains("[scanner]", ignoreCase = true) ||
                                    line.contains("[route]", ignoreCase = true) ||
                                    line.contains("[ping]", ignoreCase = true) -> Color(0xFF67E4A6)
                                else -> Color(0xFFDCE2EE)
                            }
                            Text(
                                text = line,
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.bodySmall,
                                color = lineColor
                            )
                        }
                    }
                }
            }

            Text(
                text = "Showing ${filteredLogs.size} of ${logLines.size} buffered lines",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun LiveLogsTab(
    logLines: List<String>,
    isServiceRunning: Boolean,
    onClearLogs: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("live_logs_tab")
    ) {
        RealTimeLogDisplay(
            logLines = logLines,
            isServiceRunning = isServiceRunning,
            onClearLogs = onClearLogs,
            terminalHeight = 380.dp
        )
    }
}

@Composable
fun ConfigJsonDialog(
    config: SpoofConfig,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val jsonText = remember(config) { config.toJsonString(2) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generated config.json") },
        text = {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = Color(0xFF13161C),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = jsonText,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFFDCE2EE),
                    modifier = Modifier.padding(12.dp)
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    copyToClipboard(context, "config.json", jsonText)
                    onDismiss()
                }
            ) {
                Text("Copy JSON")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
fun SaveProfileDialog(
    defaultName: String,
    onSave: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var name by remember { mutableStateOf(defaultName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Save Server Profile") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Profile Name") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("profile_name_input")
            )
        },
        confirmButton = {
            Button(
                onClick = { onSave(name) },
                modifier = Modifier.testTag("confirm_save_profile_button")
            ) {
                Text("Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

fun copyToClipboard(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText(label, text))
    Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
}
