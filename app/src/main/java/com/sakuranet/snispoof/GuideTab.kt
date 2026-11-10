package com.sakuranet.snispoof

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun GuideScreen(
    context: Context,
    listenPort: String,
    onNavigateToSettings: () -> Unit,
    onNavigateToBenchmark: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("guide_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Welcome Header Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.35f))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = "SakuraNet SNI Knowledge Base & Integration",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Complete guide for coexisting with v2rayNG / Xray clients, deep packet inspection bypass methods, byte fragmentation, and troubleshooting.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Section 1: v2rayNG Integration & VPN Mode Fix
        GuideExpandableSection(
            title = "🌸 v2rayNG Integration & VPN Coexistence",
            subtitle = "Prevent connection loops when v2rayNG VPN mode is active",
            defaultExpanded = true
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Root Cause:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "When v2rayNG activates VPN mode, Android routes all system traffic into a virtual network interface (tun0). If SakuraNet SNI Spoof is also captured by this tunnel, proxy traffic enters a routing loop and immediately aborts.",
                    style = MaterialTheme.typography.bodySmall
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

                Text(
                    text = "Step-by-step Setup Guide:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )

                StepCard(
                    stepNumber = "1",
                    title = "Exclude SakuraNet in v2rayNG (Crucial)",
                    description = "Open v2rayNG → Menu (top-left) → Settings → Per-app proxy. Set the mode to 'Bypass selected apps' and check SakuraNet SNI Spoof (com.sakuranet.snispoof) so its outbound sockets bypass the VPN interface."
                )

                StepCard(
                    stepNumber = "2",
                    title = "Point v2rayNG Inbound to Local Proxy",
                    description = "Edit your profile (VLESS / VMess / Trojan):\n• Address: 127.0.0.1\n• Port: $listenPort (matches SakuraNet local listener port)\n• Leave your TLS / Reality settings intact."
                )

                StepCard(
                    stepNumber = "3",
                    title = "Configure Upstream Target in SakuraNet",
                    description = "On the SakuraNet Dashboard tab, enter your server's real IP and an unblocked clean SNI domain (e.g. speed.cloudflare.com), then tap 'Start Proxy'."
                )

                StepCard(
                    stepNumber = "4",
                    title = "Physical Interface Binding Active",
                    description = "SakuraNet automatically binds outbound upstream sockets directly to physical network adapters (Wi-Fi wlan0 or Cellular rmnet0), ensuring packets reach the edge server even while v2rayNG VPN is connected."
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            copyToClipboard(context, "Package Name", "com.sakuranet.snispoof")
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Copy Package Name", style = MaterialTheme.typography.labelSmall)
                    }
                    Button(
                        onClick = {
                            copyToClipboard(context, "Local Endpoint", "127.0.0.1:$listenPort")
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Copy 127.0.0.1:$listenPort", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }

        // Section 2: All 7 Spoofing Methods Explained
        GuideExpandableSection(
            title = "🛡️ 7 DPI Bypass & Anti-Censorship Methods",
            subtitle = "Detailed technical overview of available evasion techniques",
            defaultExpanded = false
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                MethodDetailCard(
                    name = "1. Combined (Boundary Slice + Decoy) [Recommended]",
                    detail = "Transmits a low-TTL decoy ClientHello with a clean SNI to desynchronize DPI state tracking, followed by micro-sliced real handshake segments. Highest bypass rate on restrictive mobile networks."
                )
                MethodDetailCard(
                    name = "2. Byte-Range Slicing (Byte-Range Fragment)",
                    detail = "Carves the TLS ClientHello at exact custom byte intervals (e.g. 1-5, 8-24, 32-64) with dynamic 5-15ms delays, preventing DPI reassembly buffers from extracting the filtered domain."
                )
                MethodDetailCard(
                    name = "3. TLS Record Slicing (RFC Compliant)",
                    detail = "Divides the single ClientHello handshake across multiple legitimate TLS record frames (0x16 0x03) at the protocol layer. TCP headers remain standard, evading firewalls that block TCP fragmentation."
                )
                MethodDetailCard(
                    name = "4. TCP Out-Of-Order Evasion (Disorder)",
                    detail = "Transmits the tail segments of the handshake before the initial segments. Defeats stateful hardware DPI appliances with small memory buffers while the target server reassembles in order."
                )
                MethodDetailCard(
                    name = "5. Out-Of-Band (TCP URG) Decoy",
                    detail = "Injects an urgent byte (TCP URG flag) inside the SNI segment. DPI middlebox parsers lose synchronization and skip analyzing the actual SNI."
                )
                MethodDetailCard(
                    name = "6. SNI Extension Boundary Slice",
                    detail = "Slices the packet directly at the Server Name Indication extension offset (0x0000), placing half the hostname in one segment and half in the next."
                )
                MethodDetailCard(
                    name = "7. Fake SNI First Handshake",
                    detail = "Initiates a transient handshake with a benign domain to mark the connection 5-tuple as cleared in stateful tracking tables before transmitting real traffic."
                )

                Button(
                    onClick = onNavigateToBenchmark,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Open Automated Benchmark Tool")
                }
            }
        }

        // Section 3: Obfuscation and Advanced Parameters
        GuideExpandableSection(
            title = "🎭 Advanced Obfuscation & Camouflage",
            subtitle = "RFC 7685 padding, GREASE extensions, and SNI case randomization",
            defaultExpanded = false
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "These options only change the low-TTL decoy packet (Combined, Disorder and Inject methods). " +
                        "The real ClientHello is never edited: every byte of it is covered by the TLS transcript hash, " +
                        "so changing it would make the server abort the handshake.",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold
                )

                Text(
                    text = "• SNI Case Obfuscation:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Randomizes letter case (e.g. wWw.GoOgLe.CoM). DNS is case-insensitive, but simple text-based DPI pattern matchers fail to match blacklisted signatures.",
                    style = MaterialTheme.typography.bodySmall
                )

                Text(
                    text = "• Standard TLS Padding (RFC 7685):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Extends the ClientHello length with random neutral bytes to prevent packet size signature identification.",
                    style = MaterialTheme.typography.bodySmall
                )

                Text(
                    text = "• GREASE Extensions (RFC 8701):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Injects standard random GREASE identifiers to emulate modern Google Chrome and Mozilla Firefox browser handshakes.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // Section 4: Troubleshooting
        GuideExpandableSection(
            title = "⚠️ Troubleshooting Common Errors",
            subtitle = "Diagnostics for connection reset, abort, and timeouts",
            defaultExpanded = false
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Error: 'Software caused connection abort' (TCP RST):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
                Text(
                    text = "The DPI middlebox detected a forbidden keyword and injected a TCP RST packet.\nRecommended fixes:\n1. Switch method to Combined or TLS Record Slicing.\n2. Try another fragmentation strategy (SNI Micro-Slice or Byte-Range) in Settings.\n3. Choose an alternative clean Fake SNI from the Scanner tab.",
                    style = MaterialTheme.typography.bodySmall
                )

                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

                Text(
                    text = "Error: 'Connection timed out':",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFE65100)
                )
                Text(
                    text = "Packets were silently dropped along the route by the ISP.\nRecommended fixes:\n1. Open the 'SNI Scanner' tab and probe for responsive hostnames with low latency.\n2. Run the 'Benchmark' tool to test which bypass technique receives a valid ServerHello.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
fun GuideExpandableSection(
    title: String,
    subtitle: String,
    defaultExpanded: Boolean = false,
    content: @Composable () -> Unit
) {
    var expanded by remember { mutableStateOf(defaultExpanded) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    text = if (expanded) "▲" else "▼",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp)
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
fun StepCard(
    stepNumber: String,
    title: String,
    description: String
) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            verticalAlignment = Alignment.Top
        ) {
            Surface(
                shape = RoundedCornerShape(50),
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        text = stepNumber,
                        color = MaterialTheme.colorScheme.onPrimary,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun MethodDetailCard(
    name: String,
    detail: String
) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp)
        ) {
            Text(
                text = name,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
