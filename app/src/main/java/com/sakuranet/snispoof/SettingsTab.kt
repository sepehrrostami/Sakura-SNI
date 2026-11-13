package com.sakuranet.snispoof

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object ApkExporter {
    const val DEFAULT_APK_NAME = "SakuraNet-SNI-Spoof.apk"

    fun getInstalledApkFile(context: Context): File? {
        return runCatching {
            val path = context.applicationInfo.sourceDir
            if (path.isNullOrBlank()) null else File(path).takeIf { it.exists() && it.canRead() }
        }.getOrNull()
    }

    fun exportToDownloads(context: Context): Result<String> {
        return runCatching {
            val srcApk = getInstalledApkFile(context)
                ?: throw IllegalStateException("Installed APK sourceDir not accessible")
            val sizeKb = srcApk.length() / 1024

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                // Remove previous entry with same name if owned by our package
                runCatching {
                    resolver.delete(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        "${MediaStore.MediaColumns.DISPLAY_NAME} = ?",
                        arrayOf(DEFAULT_APK_NAME)
                    )
                }
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, DEFAULT_APK_NAME)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/vnd.android.package-archive")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("MediaStore could not create output entry in Downloads")
                resolver.openOutputStream(uri)?.use { out ->
                    FileInputStream(srcApk).use { input ->
                        input.copyTo(out)
                    }
                } ?: throw IllegalStateException("Could not open output stream for Downloads")
                val doneValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.IS_PENDING, 0)
                }
                resolver.update(uri, doneValues, null, null)
                "Download/$DEFAULT_APK_NAME (${sizeKb} KB)"
            } else {
                @Suppress("DEPRECATION")
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                downloadsDir.mkdirs()
                val dstFile = File(downloadsDir, DEFAULT_APK_NAME)
                FileInputStream(srcApk).use { input ->
                    FileOutputStream(dstFile).use { out ->
                        input.copyTo(out)
                    }
                }
                "${dstFile.absolutePath} (${sizeKb} KB)"
            }
        }
    }

    fun exportToUri(context: Context, destUri: Uri): Result<String> {
        return runCatching {
            val srcApk = getInstalledApkFile(context)
                ?: throw IllegalStateException("Installed APK sourceDir not accessible")
            val sizeKb = srcApk.length() / 1024
            context.contentResolver.openOutputStream(destUri)?.use { out ->
                FileInputStream(srcApk).use { input ->
                    input.copyTo(out)
                }
            } ?: throw IllegalStateException("Unable to open chosen destination file")
            "Saved APK (${sizeKb} KB)"
        }
    }
}

private enum class SettingsCategory(val id: String, val label: String) {
    ALL("all", "All Sections"),
    ADS("ads", "📢 AdMob Ads"),
    APK("apk", "📦 APK Export"),
    ENGINE("engine", "🛡️ Engine & VPN"),
    FRAGMENT("fragment", "✂️ Fragmentation"),
    OBFUSCATION("obfuscation", "🎭 Obfuscation"),
    NETWORK("network", "⏱️ Timeouts & Port")
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    context: Context,
    engineMode: String,
    onEngineModeChange: (String) -> Unit,
    bypassVpnTun: Boolean,
    onBypassVpnTunChange: (Boolean) -> Unit,
    hasRoot: Boolean?,
    listenPort: String,
    onListenPortChange: (String) -> Unit,
    fragmentStrategy: String,
    onFragmentStrategyChange: (String) -> Unit,
    byteRangeSpec: String,
    onByteRangeSpecChange: (String) -> Unit,
    delayRangeSpec: String,
    onDelayRangeSpecChange: (String) -> Unit,
    sniOffsetShift: String,
    onSniOffsetShiftChange: (String) -> Unit,
    chunkSize: String,
    onChunkSizeChange: (String) -> Unit,
    fragmentCount: String,
    onFragmentCountChange: (String) -> Unit,
    fragmentDelayMs: String,
    onFragmentDelayMsChange: (String) -> Unit,
    connectTimeoutMs: String,
    onConnectTimeoutMsChange: (String) -> Unit,
    handshakeTimeoutMs: String,
    onHandshakeTimeoutMsChange: (String) -> Unit,
    sniCaseObfuscation: String,
    onSniCaseObfuscationChange: (String) -> Unit,
    tlsPaddingSize: String,
    onTlsPaddingSizeChange: (String) -> Unit,
    greaseObfuscation: Boolean,
    onGreaseObfuscationChange: (Boolean) -> Unit,
    tlsRecordVersionCap: String,
    onTlsRecordVersionCapChange: (String) -> Unit,
    decoyTtl: String,
    onDecoyTtlChange: (String) -> Unit,
    decoyPayloadMode: String,
    onDecoyPayloadModeChange: (String) -> Unit,
    decoyRepeats: String,
    onDecoyRepeatsChange: (String) -> Unit,
    tcpNoDelay: Boolean,
    onTcpNoDelayChange: (Boolean) -> Unit,
    logLevel: String,
    onLogLevelChange: (String) -> Unit,
    deviceNetStatus: DeviceNetworkStatus,
    adMobState: AdMobUiState,
    onReloadAds: () -> Unit,
    apkExportStatus: String?,
    onSaveApkToDownloads: () -> Unit,
    onSaveApkAs: () -> Unit,
    onResetDefaults: () -> Unit,
    modifier: Modifier = Modifier
) {
    var selectedCategory by remember { mutableStateOf(SettingsCategory.ALL) }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("settings_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Category Filter Strip for Easy Navigation
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = "Settings Categories (Tap to filter):",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    SettingsCategory.entries.forEach { cat ->
                        FilterChip(
                            selected = selectedCategory == cat,
                            onClick = { selectedCategory = cat },
                            label = {
                                Text(
                                    text = cat.label,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = if (selectedCategory == cat) FontWeight.Bold else FontWeight.Normal
                                )
                            },
                            modifier = Modifier.testTag("settings_category_${cat.id}")
                        )
                    }
                }
            }
        }

        // Section 0: Google Mobile Ads Next-Gen SDK Configuration
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.ADS) {
            var storedIds by remember { mutableStateOf(AdMobConfigStore.load(context)) }
            var appIdInput by remember(storedIds) { mutableStateOf(storedIds.appId) }
            var connectUnitInput by remember(storedIds) { mutableStateOf(storedIds.connectRewardedUnitId) }
            var disconnectUnitInput by remember(storedIds) { mutableStateOf(storedIds.disconnectInterstitialUnitId) }

            SettingsGroupCard(
                badge = "NEXT-GEN GMA SDK",
                title = "Google AdMob Connect & Disconnect Ads",
                subtitle = "Rewarded & Interstitial ads via com.google.android.libraries.ads.mobile.sdk"
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "SDK Initialized: ${if (adMobState.isInitialized) "Yes" else if (adMobState.isInitializing) "Initializing…" else "Pending"} • " +
                                    "Mode: ${if (adMobState.isTestMode) "Google Test IDs" else "Custom IDs"}",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Connect Rewarded: ${if (adMobState.connectAdReady) "Ready" else "Not cached"} | " +
                                    "Disconnect Interstitial: ${if (adMobState.disconnectAdReady) "Ready" else "Not cached"} | " +
                                    "Completed: ${adMobState.totalAdsCompleted}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    OutlinedTextField(
                        value = appIdInput,
                        onValueChange = { appIdInput = it },
                        label = { Text("AdMob App ID") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("admob_app_id_input")
                    )

                    OutlinedTextField(
                        value = connectUnitInput,
                        onValueChange = { connectUnitInput = it },
                        label = { Text("Connect Rewarded Ad Unit ID") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("admob_connect_unit_input")
                    )

                    OutlinedTextField(
                        value = disconnectUnitInput,
                        onValueChange = { disconnectUnitInput = it },
                        label = { Text("Disconnect Interstitial Ad Unit ID") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("admob_disconnect_unit_input")
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                val updated = AdMobIdsConfig(
                                    appId = appIdInput.trim(),
                                    connectRewardedUnitId = connectUnitInput.trim(),
                                    disconnectInterstitialUnitId = disconnectUnitInput.trim()
                                )
                                AdMobConfigStore.save(context, updated)
                                storedIds = AdMobConfigStore.load(context)
                                AdMobManager.initialize(context, forceReinit = true)
                                onReloadAds()
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("save_admob_ids_button")
                        ) {
                            Text("Save & Reload Ads", fontWeight = FontWeight.SemiBold)
                        }

                        OutlinedButton(
                            onClick = {
                                storedIds = AdMobConfigStore.reset(context)
                                AdMobManager.initialize(context, forceReinit = true)
                                onReloadAds()
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("reset_admob_ids_button")
                        ) {
                            Text("Use Test IDs", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }

        // Section 1: Manual APK Export to Device Storage
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.APK) {
            SettingsGroupCard(
                badge = "MANUAL TOOL",
                title = "Manual APK Export (Install on Other Phones)",
                subtitle = "Manually save a copy of the installed APK file when you want to transfer or install it on another device"
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onSaveApkToDownloads,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("save_apk_downloads_button")
                        ) {
                            Text(
                                text = "Save to Downloads",
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        OutlinedButton(
                            onClick = onSaveApkAs,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("save_apk_picker_button")
                        ) {
                            Text(
                                text = "Save APK As…",
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }

                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = apkExportStatus
                                ?: "Manual mode active • Tap a button above to export Download/${ApkExporter.DEFAULT_APK_NAME}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }
            }
        }

        // Section 2: Engine Architecture & VPN Coexistence
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.ENGINE) {
            SettingsGroupCard(
                badge = "CORE ENGINE",
                title = "Engine Mode & v2rayNG VPN Coexistence",
                subtitle = "Configure socket transport and direct physical network binding"
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        val isKotlin = engineMode != "native_binary"
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (isKotlin) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                            border = BorderStroke(
                                1.5.dp,
                                if (isKotlin) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                            ),
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .clickable { onEngineModeChange("vpn_safe_kotlin") }
                                .testTag("settings_engine_kotlin")
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "VPN-Safe Engine (Recommended)",
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(Modifier.height(2.dp))
                                Text(
                                    text = "Binds upstream sockets directly to Wi-Fi/Cellular so it never drops when v2rayNG VPN starts",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        val isNative = engineMode == "native_binary"
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (isNative) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                            border = BorderStroke(
                                1.5.dp,
                                if (isNative) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                            ),
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .clickable { onEngineModeChange("native_binary") }
                                .testTag("settings_engine_native")
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "Native Binary (Root su)",
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(Modifier.height(2.dp))
                                Text(
                                    text = if (hasRoot == true) "Root access confirmed (High throughput)" else "Requires root privilege (su)",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Bypass Virtual VPN Tunnel (tun0)",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Prevents upstream proxy sockets from looping back into v2rayNG VPN routing tables",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = bypassVpnTun,
                            onCheckedChange = onBypassVpnTunChange,
                            modifier = Modifier.testTag("settings_bypass_vpn_switch")
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
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
                                text = "Physical Interface: ${deviceNetStatus.physicalInterface}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                            TextButton(
                                onClick = {
                                    copyToClipboard(context, "Package Name", context.packageName)
                                }
                            ) {
                                Text("Copy App ID", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }

        // Section 3: Fragmentation Strategies & Byte Ranges
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.FRAGMENT) {
            SettingsGroupCard(
                badge = "PACKET SLICING",
                title = "Fragmentation Strategies & Byte Ranges",
                subtitle = "Configure exact slicing positions and delays for TLS ClientHello payloads"
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Fragmentation Strategy:",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        // Use the engine's canonical strategy ids. The old hard-coded list offered
                        // "record_split" / "disorder" / "oob", which are methods, not strategies,
                        // so the engine silently fell back to a midpoint split.
                        val strategies = SpoofConfig.STRATEGY_METAS.map { it.id to it.title }
                        for ((id, label) in strategies) {
                            FilterChip(
                                selected = fragmentStrategy == id,
                                onClick = { onFragmentStrategyChange(id) },
                                label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                                modifier = Modifier.testTag("strategy_chip_$id")
                            )
                        }
                    }

                    OutlinedTextField(
                        value = byteRangeSpec,
                        onValueChange = onByteRangeSpecChange,
                        label = { Text("Byte Range Specification") },
                        supportingText = { Text("Quick presets below (e.g. 1-5, 8-24, 32-64)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )

                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        for (preset in SpoofConfig.BYTE_RANGE_PRESETS) {
                            SuggestionChip(
                                onClick = { onByteRangeSpecChange(preset) },
                                label = { Text(preset, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = delayRangeSpec,
                            onValueChange = onDelayRangeSpecChange,
                            label = { Text("Delay Range (ms)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = sniOffsetShift,
                            onValueChange = onSniOffsetShiftChange,
                            label = { Text("SNI Offset Shift") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = chunkSize,
                            onValueChange = onChunkSizeChange,
                            label = { Text("Chunk Size (bytes)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                        OutlinedTextField(
                            value = fragmentCount,
                            onValueChange = onFragmentCountChange,
                            label = { Text("Fragment Count") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                    }
                }
            }
        }

        // Section 4: Obfuscation and DPI Camouflage
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.OBFUSCATION) {
            SettingsGroupCard(
                badge = "DPI CAMOUFLAGE",
                title = "Traffic Obfuscation & Camouflage",
                subtitle = "SNI case, GREASE and padding change the DECOY packet only (Combined / Disorder / Inject). " +
                    "Editing the real ClientHello would break the TLS handshake."
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = "SNI Case Randomization:",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = "Transforms the decoy's hostname case (e.g. wWw.GoOgLe.CoM)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            for (opt in SpoofConfig.SNI_CASE_MODES) {
                                FilterChip(
                                    selected = sniCaseObfuscation == opt.id,
                                    onClick = { onSniCaseObfuscationChange(opt.id) },
                                    label = { Text(opt.title, style = MaterialTheme.typography.labelSmall) },
                                    modifier = Modifier.testTag("settings_sni_case_${opt.id}")
                                )
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Standard GREASE Extensions (RFC 8701)",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Adds a random GREASE extension to the decoy ClientHello",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = greaseObfuscation,
                            onCheckedChange = onGreaseObfuscationChange,
                            modifier = Modifier.testTag("settings_grease_switch")
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = tlsPaddingSize,
                            onValueChange = onTlsPaddingSizeChange,
                            label = { Text("TLS Padding (bytes)") },
                            supportingText = { Text("Decoy only, RFC 7685 (0 to 512)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )

                        OutlinedTextField(
                            value = decoyTtl,
                            onValueChange = onDecoyTtlChange,
                            label = { Text("Decoy Packet TTL") },
                            supportingText = { Text("Usually 3 to 6 hops") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = decoyPayloadMode,
                            onValueChange = onDecoyPayloadModeChange,
                            label = { Text("Decoy Payload Mode") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        OutlinedTextField(
                            value = tlsRecordVersionCap,
                            onValueChange = onTlsRecordVersionCapChange,
                            label = { Text("TLS Record Version") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                    }
                }
            }
        }

        // Section 5: Timeouts and Network
        if (selectedCategory == SettingsCategory.ALL || selectedCategory == SettingsCategory.NETWORK) {
            SettingsGroupCard(
                badge = "SOCKET & TIMING",
                title = "Timeouts & Network Configuration",
                subtitle = "Local listener port, connection timeouts, and socket acceleration"
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = listenPort,
                            onValueChange = onListenPortChange,
                            label = { Text("Local Listener Port") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                        OutlinedTextField(
                            value = fragmentDelayMs,
                            onValueChange = onFragmentDelayMsChange,
                            label = { Text("Inter-Fragment Delay (ms)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedTextField(
                            value = connectTimeoutMs,
                            onValueChange = onConnectTimeoutMsChange,
                            label = { Text("TCP Connect Timeout (ms)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                        OutlinedTextField(
                            value = handshakeTimeoutMs,
                            onValueChange = onHandshakeTimeoutMsChange,
                            label = { Text("TLS Handshake Timeout (ms)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Socket Accelerator (TCP_NODELAY)",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Disables Nagle's algorithm for immediate dispatch of fragmented frames",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = tcpNoDelay,
                            onCheckedChange = onTcpNoDelayChange,
                            modifier = Modifier.testTag("settings_tcp_nodelay_switch")
                        )
                    }
                }
            }
        }

        // Section: Reset to Defaults
        OutlinedButton(
            onClick = onResetDefaults,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.5f)),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag("reset_defaults_button")
        ) {
            Text("Reset All Settings to Factory Defaults")
        }
    }
}

@Composable
fun SettingsGroupCard(
    title: String,
    subtitle: String,
    badge: String? = null,
    defaultExpanded: Boolean = true,
    content: @Composable () -> Unit
) {
    var expanded by remember { mutableStateOf(defaultExpanded) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    if (badge != null) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.primaryContainer,
                            modifier = Modifier.padding(bottom = 4.dp)
                        ) {
                            Text(
                                text = badge,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
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
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                    content()
                }
            }
        }
    }
}
