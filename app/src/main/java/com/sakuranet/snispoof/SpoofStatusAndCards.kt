package com.sakuranet.snispoof

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

@Composable
fun NoInternetWarningBanner(
    isProxyRunning: Boolean,
    transportLabel: String,
    modifier: Modifier = Modifier
) {
    val bannerContainer = if (isProxyRunning) {
        MaterialTheme.colorScheme.errorContainer
    } else {
        Color(0xFFFFF4E5)
    }
    val bannerBorder = if (isProxyRunning) {
        MaterialTheme.colorScheme.error
    } else {
        Color(0xFFE65100).copy(alpha = 0.55f)
    }
    val bannerContentColor = if (isProxyRunning) {
        MaterialTheme.colorScheme.onErrorContainer
    } else {
        Color(0xFF663C00)
    }
    val warningTitle = stringResource(R.string.warning_no_internet_title)
    val warningBody = if (isProxyRunning) {
        stringResource(R.string.warning_no_internet_proxy_active)
    } else {
        stringResource(R.string.warning_no_internet_idle)
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag("no_internet_warning_banner")
            .semantics { contentDescription = "$warningTitle: $warningBody" },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = bannerContainer),
        border = BorderStroke(1.5.dp, bannerBorder)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(if (isProxyRunning) MaterialTheme.colorScheme.error else Color(0xFFE65100))
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = warningTitle,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = bannerContentColor,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.width(6.dp))
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = bannerBorder.copy(alpha = 0.16f)
                    ) {
                        Text(
                            text = if (isProxyRunning) "PROXY IMPACTED • $transportLabel" else transportLabel,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = bannerContentColor,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = warningBody,
                    style = MaterialTheme.typography.bodySmall,
                    color = bannerContentColor
                )
            }
        }
    }
}

@Composable
fun SniServiceStatusIndicator(
    isRunning: Boolean,
    listenPort: String,
    connectIp: String,
    connectPort: String,
    fakeSni: String,
    method: String,
    modifier: Modifier = Modifier,
    wakeLockHeld: Boolean = false,
    deviceNetStatus: DeviceNetworkStatus = DeviceNetworkStatus(),
    onCopyEndpoint: () -> Unit = {}
) {
    val activeAccent = Color(0xFF1B8755)
    val trafficAccent = Color(0xFF0077C2)
    val activeContainer = Color(0xFFE7F6EE)
    val stoppedAccent = MaterialTheme.colorScheme.outline
    val stoppedContainer = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)

    val lastTrafficMs by LogBus.lastTrafficMsFlow.collectAsState()
    val relayedCount by LogBus.connectionCountFlow.collectAsState()

    var uptimeSeconds by remember(isRunning) { mutableLongStateOf(0L) }
    var telemetry by remember { mutableStateOf(ProxyTrafficTelemetry()) }

    LaunchedEffect(isRunning, listenPort, lastTrafficMs, relayedCount) {
        if (isRunning) {
            val base = LogBus.startedAtMillis().takeIf { it > 0L } ?: System.currentTimeMillis()
            var prevRx = android.net.TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
            var prevTx = android.net.TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
            var prevTimeMs = System.currentTimeMillis()

            while (true) {
                val now = System.currentTimeMillis()
                uptimeSeconds = ((now - base) / 1000L).coerceAtLeast(0L)

                val portNum = listenPort.toIntOrNull() ?: 40443
                val (bound, activeConns) = NetworkTools.inspectLocalProxySockets(portNum)

                val curRx = android.net.TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
                val curTx = android.net.TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
                val elapsedSec = ((now - prevTimeMs) / 1000f).coerceAtLeast(0.5f)
                val rxRate = ((curRx - prevRx).coerceAtLeast(0L) / elapsedSec).toLong()
                val txRate = ((curTx - prevTx).coerceAtLeast(0L) / elapsedSec).toLong()
                prevRx = curRx
                prevTx = curTx
                prevTimeMs = now

                val recentProcessTraffic = lastTrafficMs > 0L && (now - lastTrafficMs) < 3500L
                val isProcessing = activeConns > 0 || recentProcessTraffic
                val trafficState = if (isProcessing) {
                    ProxyTrafficState.PROCESSING_TRAFFIC
                } else {
                    ProxyTrafficState.IDLE_LISTENING
                }

                telemetry = ProxyTrafficTelemetry(
                    state = trafficState,
                    portBound = bound,
                    activeConnections = activeConns,
                    totalRelayedConnections = relayedCount,
                    rxBytesPerSec = rxRate,
                    txBytesPerSec = txRate
                )
                delay(1000L)
            }
        } else {
            uptimeSeconds = 0L
            telemetry = ProxyTrafficTelemetry(state = ProxyTrafficState.OFFLINE)
        }
    }

    val isProcessingTraffic = isRunning && telemetry.state == ProxyTrafficState.PROCESSING_TRAFFIC

    val containerColor by animateColorAsState(
        targetValue = if (isRunning) activeContainer else stoppedContainer,
        label = "status_container_color"
    )
    val borderColor by animateColorAsState(
        targetValue = when {
            isProcessingTraffic -> trafficAccent.copy(alpha = 0.65f)
            isRunning -> activeAccent.copy(alpha = 0.5f)
            else -> stoppedAccent.copy(alpha = 0.3f)
        },
        label = "status_border_color"
    )
    val dotColor by animateColorAsState(
        targetValue = when {
            isProcessingTraffic -> trafficAccent
            isRunning -> activeAccent
            else -> stoppedAccent
        },
        label = "status_dot_color"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "status_pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isRunning) 1.75f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = if (isProcessingTraffic) 650 else 1200,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_scale"
    )
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = if (isRunning) 0.5f else 0f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = if (isProcessingTraffic) 650 else 1200,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse_alpha"
    )

    val statusDescription = if (isRunning) {
        stringResource(R.string.status_service_running)
    } else {
        stringResource(R.string.status_service_stopped)
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag("service_status_indicator")
            .semantics { contentDescription = statusDescription },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Header Row: Status Dot + Title + Uptime Badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f).padding(end = 8.dp)
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(22.dp)
                            .testTag("service_status_dot")
                    ) {
                        if (isRunning) {
                            Box(
                                modifier = Modifier
                                    .size(12.dp)
                                    .scale(pulseScale)
                                    .clip(CircleShape)
                                    .background(dotColor.copy(alpha = pulseAlpha))
                            )
                        }
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(dotColor)
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = statusDescription,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (isRunning) Color(0xFF0E4F30) else MaterialTheme.colorScheme.onSurface
                    )
                }

                Surface(
                    shape = RoundedCornerShape(50),
                    color = if (isRunning) activeAccent else MaterialTheme.colorScheme.surfaceVariant,
                    border = if (!isRunning) BorderStroke(1.dp, stoppedAccent.copy(alpha = 0.4f)) else null,
                    modifier = Modifier.testTag("service_status_badge")
                ) {
                    val mins = uptimeSeconds / 60
                    val secs = uptimeSeconds % 60
                    val badgeText = if (isRunning) {
                        "${stringResource(R.string.status_badge_active)} • %02d:%02d".format(mins, secs)
                    } else {
                        stringResource(R.string.status_badge_idle)
                    }
                    Text(
                        text = badgeText,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (isRunning) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
            }

            // Real-Time Network Traffic & Transport Strip (Adaptive 2-row box)
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = if (isRunning) Color.White.copy(alpha = 0.82f) else MaterialTheme.colorScheme.surface.copy(alpha = 0.65f),
                border = BorderStroke(
                    1.dp,
                    if (isProcessingTraffic) trafficAccent.copy(alpha = 0.45f) else borderColor
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("network_monitor_component")
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.weight(1f)
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier
                                    .size(16.dp)
                                    .testTag("traffic_status_dot")
                            ) {
                                val trafficDotColor = when (telemetry.state) {
                                    ProxyTrafficState.PROCESSING_TRAFFIC -> trafficAccent
                                    ProxyTrafficState.IDLE_LISTENING -> activeAccent
                                    ProxyTrafficState.OFFLINE -> stoppedAccent
                                }
                                if (telemetry.state == ProxyTrafficState.PROCESSING_TRAFFIC) {
                                    Box(
                                        modifier = Modifier
                                            .size(10.dp)
                                            .scale(pulseScale)
                                            .clip(CircleShape)
                                            .background(trafficDotColor.copy(alpha = pulseAlpha))
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .clip(CircleShape)
                                        .background(trafficDotColor)
                                )
                            }
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = when (telemetry.state) {
                                    ProxyTrafficState.PROCESSING_TRAFFIC -> "PROCESSING TRAFFIC"
                                    ProxyTrafficState.IDLE_LISTENING -> "STANDBY • LISTENING"
                                    ProxyTrafficState.OFFLINE -> "TRAFFIC MONITOR OFFLINE"
                                },
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = when (telemetry.state) {
                                    ProxyTrafficState.PROCESSING_TRAFFIC -> trafficAccent
                                    ProxyTrafficState.IDLE_LISTENING -> Color(0xFF0E4F30)
                                    ProxyTrafficState.OFFLINE -> MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }

                        Text(
                            text = "Net: ${deviceNetStatus.transportLabel}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.SemiBold,
                            color = if (!deviceNetStatus.hasInternet) {
                                MaterialTheme.colorScheme.error
                            } else if (deviceNetStatus.vpnActive) {
                                trafficAccent
                            } else if (isRunning) {
                                Color(0xFF0E4F30)
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.testTag("connectivity_transport_badge")
                        )
                    }

                    HorizontalDivider(color = borderColor.copy(alpha = 0.25f))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (isRunning) {
                                "Conns: ${telemetry.activeConnections} active (${telemetry.totalRelayedConnections} total)"
                            } else {
                                "Conns: 0 active"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = if (isRunning) Color(0xFF165B3A) else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "↓${NetworkTools.formatThroughput(telemetry.rxBytesPerSec)}  ↑${NetworkTools.formatThroughput(telemetry.txBytesPerSec)}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Medium,
                            color = if (isRunning) Color(0xFF165B3A) else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (isRunning) {
                val targetEndpoint = if (connectIp.isNotBlank()) "$connectIp:$connectPort" else "edge:$connectPort"
                Text(
                    text = "127.0.0.1:$listenPort → $targetEndpoint  •  mode: $method  •  SNI: $fakeSni",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFF165B3A)
                )
                Text(
                    text = if (wakeLockHeld) {
                        "Persistent Foreground Service • CPU WakeLock • VPN-Bypass Socket Active"
                    } else {
                        "Persistent Foreground Service Active"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF0E4F30),
                    modifier = Modifier.testTag("foreground_protection_status")
                )
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = activeAccent.copy(alpha = 0.12f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "v2rayNG Address: 127.0.0.1:$listenPort",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFF0E4F30),
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "Copy",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = activeAccent,
                            modifier = Modifier
                                .clickable { onCopyEndpoint() }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                                .testTag("copy_local_endpoint_button")
                        )
                    }
                }
            } else {
                Text(
                    text = stringResource(R.string.status_subtitle_stopped),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun VpnCoexistenceCard(
    bypassVpnTun: Boolean,
    onBypassVpnTunChange: (Boolean) -> Unit,
    engineMode: String,
    onEngineModeChange: (String) -> Unit,
    deviceNetStatus: DeviceNetworkStatus,
    listenPort: String,
    onCopyPackageName: () -> Unit,
    onCopyLocalAddress: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("vpn_coexistence_card"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f)
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary.copy(alpha = 0.3f))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "v2rayNG VPN-Mode Coexistence",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = if (deviceNetStatus.vpnActive) {
                            "VPN Tunnel Active • Outbound bound directly to ${deviceNetStatus.physicalInterface}"
                        } else {
                            "Physical Interface Ready: ${deviceNetStatus.physicalInterface} (Bypasses tun0 when VPN starts)"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = bypassVpnTun,
                    onCheckedChange = onBypassVpnTunChange,
                    modifier = Modifier.testTag("bypass_vpn_switch")
                )
            }

            // Engine Mode Selector (2 clean proportional cards)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                val isKotlinEngine = engineMode != "native_binary"
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isKotlinEngine) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surface
                    },
                    border = BorderStroke(
                        1.5.dp,
                        if (isKotlinEngine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { onEngineModeChange("vpn_safe_kotlin") }
                        .testTag("engine_mode_vpn_safe")
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = "VPN-Safe Engine",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "App-UID + Physical Socket Bind (Works with v2rayNG VPN)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (!isKotlinEngine) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surface
                    },
                    border = BorderStroke(
                        1.5.dp,
                        if (!isKotlinEngine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { onEngineModeChange("native_binary") }
                        .testTag("engine_mode_native_binary")
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = "Native Go Binary",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "sakura-sni + Root ip rule table bypass",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onCopyLocalAddress,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 42.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = "Copy 127.0.0.1:$listenPort",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                OutlinedButton(
                    onClick = onCopyPackageName,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 42.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = "Copy App ID (Bypass)",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}
