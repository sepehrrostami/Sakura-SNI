package com.sakuranet.snispoof

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

enum class AppScreen(val titleRes: Int) {
    HOME(R.string.nav_home),
    SETTINGS(R.string.nav_settings),
    LOGS(R.string.nav_logs),
    SCANNER(R.string.nav_scanner),
    BENCHMARK(R.string.nav_benchmark),
    GUIDE(R.string.nav_guide)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        NetworkTools.ensurePhysicalNetworkTracker(applicationContext)
        enableEdgeToEdge()
        setContent { AppRoot() }
    }

    override fun onResume() {
        super.onResume()
        NetworkTools.ensurePhysicalNetworkTracker(applicationContext)
        SniSpoofService.ensureRunningIfSavedActive(applicationContext)
    }
}

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val initialCfg = remember { ProfileStore.loadActiveConfig(context) }
    var profiles by remember { mutableStateOf(ProfileStore.loadProfiles(context)) }
    var activeProfileId by remember { mutableStateOf<String?>(null) }

    var hasRoot by remember { mutableStateOf<Boolean?>(null) }
    var connectIp by remember { mutableStateOf(initialCfg.connectIp) }
    var connectPort by remember { mutableStateOf(initialCfg.connectPort.toString()) }
    var listenPort by remember { mutableStateOf(initialCfg.listenPort.toString()) }
    var fakeSni by remember { mutableStateOf(initialCfg.fakeSni) }
    var method by remember { mutableStateOf(initialCfg.method) }
    var fragmentStrategy by remember { mutableStateOf(initialCfg.fragmentStrategy) }
    var fragmentDelayMs by remember { mutableStateOf(initialCfg.fragmentDelayMs.toString()) }
    var handshakeTimeoutMs by remember { mutableStateOf(initialCfg.handshakeTimeoutMs.toString()) }
    var connectTimeoutMs by remember { mutableStateOf(initialCfg.connectTimeoutMs.toString()) }
    var logLevel by remember { mutableStateOf(initialCfg.logLevel) }
    var engineMode by remember { mutableStateOf(initialCfg.engineMode) }
    var bypassVpnTun by remember { mutableStateOf(initialCfg.bypassVpnTun) }
    var decoyTtl by remember { mutableStateOf(initialCfg.decoyTtl.toString()) }
    var chunkSize by remember { mutableStateOf(initialCfg.chunkSize.toString()) }
    var fragmentCount by remember { mutableStateOf(initialCfg.fragmentCount.toString()) }
    var tcpNoDelay by remember { mutableStateOf(initialCfg.tcpNoDelay) }
    var byteRangeSpec by remember { mutableStateOf(initialCfg.byteRangeSpec) }
    var delayRangeSpec by remember { mutableStateOf(initialCfg.delayRangeSpec) }
    var sniOffsetShift by remember { mutableStateOf(initialCfg.sniOffsetShift.toString()) }
    var sniCaseObfuscation by remember { mutableStateOf(initialCfg.sniCaseObfuscation) }
    var tlsPaddingSize by remember { mutableStateOf(initialCfg.tlsPaddingSize.toString()) }
    var greaseObfuscation by remember { mutableStateOf(initialCfg.greaseObfuscation) }
    var tlsRecordVersionCap by remember { mutableStateOf(initialCfg.tlsRecordVersionCap) }
    var decoyPayloadMode by remember { mutableStateOf(initialCfg.decoyPayloadMode) }
    var decoyRepeats by remember { mutableStateOf(initialCfg.decoyRepeats.toString()) }

    val running by LogBus.runningFlow.collectAsState()
    val wakeLockHeld by LogBus.wakeLockFlow.collectAsState()
    val logLines by LogBus.linesFlow.collectAsState()
    val deviceNetStatus by remember(context) {
        NetworkTools.observeNetworkConnectivity(context)
    }.collectAsState(
        initial = remember(context) { NetworkTools.queryCurrentNetworkStatus(context) }
    )

    var currentScreen by remember { mutableStateOf(AppScreen.HOME) }
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)

    var showMethodDetails by remember { mutableStateOf(false) }

    var isResolvingDns by remember { mutableStateOf(false) }
    var resolvedIps by remember { mutableStateOf<List<String>>(emptyList()) }
    var dnsError by remember { mutableStateOf<String?>(null) }

    var isTestingTcp by remember { mutableStateOf(false) }
    var tcpProbeResult by remember { mutableStateOf<TcpProbeResult?>(null) }

    var showConfigJsonDialog by remember { mutableStateOf(false) }
    var showSaveProfileDialog by remember { mutableStateOf(false) }

    val currentSpoofConfig = remember(
        listenPort, connectIp, connectPort, fakeSni, method,
        fragmentStrategy, fragmentDelayMs, handshakeTimeoutMs, connectTimeoutMs, logLevel,
        engineMode, bypassVpnTun, decoyTtl, chunkSize, fragmentCount, tcpNoDelay,
        byteRangeSpec, delayRangeSpec, sniOffsetShift, sniCaseObfuscation,
        tlsPaddingSize, greaseObfuscation, tlsRecordVersionCap, decoyPayloadMode, decoyRepeats
    ) {
        SpoofConfig(
            listenPort = listenPort.toIntOrNull() ?: 40443,
            connectIp = connectIp.trim(),
            connectPort = connectPort.toIntOrNull() ?: 443,
            fakeSni = fakeSni.trim(),
            method = method,
            fragmentStrategy = fragmentStrategy,
            fragmentDelayMs = fragmentDelayMs.toIntOrNull() ?: 10,
            handshakeTimeoutMs = handshakeTimeoutMs.toIntOrNull() ?: 2500,
            connectTimeoutMs = connectTimeoutMs.toIntOrNull() ?: 5000,
            logLevel = logLevel,
            engineMode = engineMode,
            bypassVpnTun = bypassVpnTun,
            decoyTtl = decoyTtl.toIntOrNull() ?: 4,
            chunkSize = chunkSize.toIntOrNull() ?: 24,
            fragmentCount = fragmentCount.toIntOrNull() ?: 4,
            tcpNoDelay = tcpNoDelay,
            byteRangeSpec = byteRangeSpec.trim().ifBlank { "1-5, 8-24, 32-64" },
            delayRangeSpec = delayRangeSpec.trim().ifBlank { "5-15" },
            sniOffsetShift = sniOffsetShift.toIntOrNull() ?: 2,
            sniCaseObfuscation = sniCaseObfuscation,
            tlsPaddingSize = tlsPaddingSize.toIntOrNull() ?: 0,
            greaseObfuscation = greaseObfuscation,
            tlsRecordVersionCap = tlsRecordVersionCap,
            decoyPayloadMode = decoyPayloadMode,
            decoyRepeats = decoyRepeats.toIntOrNull() ?: 1
        )
    }

    LaunchedEffect(currentSpoofConfig) {
        ProfileStore.saveActiveConfig(context, currentSpoofConfig)
    }

    var apkExportStatus by remember { mutableStateOf<String?>(null) }

    // Manual-only APK Export action (triggered exclusively by user button click in Settings)
    val saveApkToDownloadsAction: () -> Unit = {
        scope.launch {
            val res = withContext(Dispatchers.IO) {
                ApkExporter.exportToDownloads(context)
            }
            res.onSuccess { msg ->
                apkExportStatus = "Saved to device: $msg"
                LogBus.push("[apk] Manually exported APK -> $msg")
                android.widget.Toast.makeText(
                    context,
                    "Saved: $msg",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }.onFailure { err ->
                apkExportStatus = "APK export failed: ${err.message}"
                LogBus.push("[warn] APK export error: ${err.message}")
            }
        }
    }

    val createApkDocLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val res = withContext(Dispatchers.IO) {
                    ApkExporter.exportToUri(context, uri)
                }
                res.onSuccess { msg ->
                    apkExportStatus = msg
                    LogBus.push("[apk] $msg ($uri)")
                    android.widget.Toast.makeText(
                        context,
                        msg,
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }.onFailure { err ->
                    apkExportStatus = "Error: ${err.message}"
                }
            }
        }
    }

    var batteryUnrestricted by remember {
        mutableStateOf(isBatteryOptimizationIgnored(context))
    }

    val batteryOptLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        batteryUnrestricted = isBatteryOptimizationIgnored(context)
    }

    LaunchedEffect(Unit) {
        NetworkTools.ensurePhysicalNetworkTracker(context)
        SniSpoofService.ensureRunningIfSavedActive(context)
        hasRoot = withContext(Dispatchers.IO) { RootShell.isRootAvailable() }
        batteryUnrestricted = isBatteryOptimizationIgnored(context)
    }

    var hadInternetWhileRunning by remember { mutableStateOf(true) }
    LaunchedEffect(deviceNetStatus.hasInternet, running) {
        if (running) {
            if (!deviceNetStatus.hasInternet) {
                hadInternetWhileRunning = false
                LogBus.push("[warn] ConnectivityManager: Device lost internet access (${deviceNetStatus.transportLabel}) while SNI proxy service is running!")
            } else if (!hadInternetWhileRunning) {
                hadInternetWhileRunning = true
                LogBus.push("[net] ConnectivityManager: Internet connection restored via ${deviceNetStatus.transportLabel}")
            }
        } else {
            hadInternetWhileRunning = deviceNetStatus.hasInternet
        }
    }

    val startProxyAction: () -> Unit = {
        scope.launch {
            try {
                NetworkTools.ensurePhysicalNetworkTracker(context)
                ProfileStore.saveActiveConfig(context, currentSpoofConfig)
                val filesDir = context.filesDir
                val bin = withContext(Dispatchers.IO) {
                    runCatching { RootShell.installBinary(context, filesDir) }
                        .getOrElse { File(filesDir, "sakura-sni") }
                }
                val cfgFile = File(filesDir, "config.json")
                withContext(Dispatchers.IO) {
                    currentSpoofConfig.writeTo(cfgFile)
                }
                val useRoot = (hasRoot == true)
                val routeSummary = "127.0.0.1:$listenPort → ${connectIp.trim()}:$connectPort ($method/$fragmentStrategy • ${fakeSni.trim()})"
                SniSpoofService.start(
                    context = context,
                    bin = bin,
                    config = cfgFile,
                    useRoot = useRoot,
                    method = method,
                    routeSummary = routeSummary
                )
            } catch (e: Exception) {
                LogBus.push("[error] Could not prepare proxy files: ${e.message}")
            }
        }
    }

    val notifPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ ->
        startProxyAction()
    }

    BackHandler(enabled = drawerState.isOpen || currentScreen != AppScreen.HOME) {
        if (drawerState.isOpen) {
            scope.launch { drawerState.close() }
        } else {
            currentScreen = AppScreen.HOME
        }
    }

    val navigateTo: (AppScreen) -> Unit = { destination ->
        currentScreen = destination
        scope.launch { drawerState.close() }
    }

    MaterialTheme {
        ModalNavigationDrawer(
            drawerState = drawerState,
            modifier = Modifier.testTag("navigation_drawer"),
            drawerContent = {
                ModalDrawerSheet(
                    modifier = Modifier
                        .widthIn(max = 310.dp)
                        .verticalScroll(rememberScrollState())
                        .testTag("navigation_drawer_sheet")
                ) {
                    // Drawer Brand & Service Status Header
                    Surface(
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 20.dp, vertical = 20.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Image(
                                    painter = painterResource(id = R.drawable.ic_sakura_logo),
                                    contentDescription = "SakuraNet App Logo",
                                    modifier = Modifier
                                        .size(48.dp)
                                        .clip(RoundedCornerShape(12.dp))
                                )
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = stringResource(R.string.app_name),
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "Physical Socket: ${deviceNetStatus.physicalInterface}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }

                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(50),
                                    color = if (running) Color(0xFF1B8755) else MaterialTheme.colorScheme.surfaceVariant
                                ) {
                                    Text(
                                        text = if (running) "PROXY ACTIVE" else "PROXY STOPPED",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = if (running) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                    )
                                }
                                Text(
                                    text = "127.0.0.1:$listenPort",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    // Primary Navigation Categories: Home, Settings, Logs
                    Text(
                        text = stringResource(R.string.drawer_section_main),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 6.dp)
                    )

                    NavigationDrawerItem(
                        label = {
                            Text(
                                text = stringResource(R.string.nav_home),
                                fontWeight = if (currentScreen == AppScreen.HOME) FontWeight.Bold else FontWeight.Medium
                            )
                        },
                        selected = currentScreen == AppScreen.HOME,
                        onClick = { navigateTo(AppScreen.HOME) },
                        icon = {
                            Icon(
                                imageVector = Icons.Default.Home,
                                contentDescription = stringResource(R.string.nav_home)
                            )
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_home")
                    )

                    NavigationDrawerItem(
                        label = {
                            Text(
                                text = stringResource(R.string.nav_settings),
                                fontWeight = if (currentScreen == AppScreen.SETTINGS) FontWeight.Bold else FontWeight.Medium
                            )
                        },
                        selected = currentScreen == AppScreen.SETTINGS,
                        onClick = { navigateTo(AppScreen.SETTINGS) },
                        icon = {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = stringResource(R.string.nav_settings)
                            )
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_settings")
                    )

                    NavigationDrawerItem(
                        label = {
                            Text(
                                text = stringResource(R.string.nav_logs),
                                fontWeight = if (currentScreen == AppScreen.LOGS) FontWeight.Bold else FontWeight.Medium
                            )
                        },
                        selected = currentScreen == AppScreen.LOGS,
                        onClick = { navigateTo(AppScreen.LOGS) },
                        icon = {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.List,
                                contentDescription = stringResource(R.string.nav_logs)
                            )
                        },
                        badge = {
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = if (running) Color(0xFF1B8755) else MaterialTheme.colorScheme.secondaryContainer
                            ) {
                                Text(
                                    text = logLines.size.toString(),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (running) Color.White else MaterialTheme.colorScheme.onSecondaryContainer,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_logs")
                    )

                    HorizontalDivider(modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp))

                    // Secondary Diagnostic Tools & Setup Guide
                    Text(
                        text = stringResource(R.string.drawer_section_tools),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 6.dp)
                    )

                    NavigationDrawerItem(
                        label = { Text(stringResource(R.string.nav_scanner)) },
                        selected = currentScreen == AppScreen.SCANNER,
                        onClick = { navigateTo(AppScreen.SCANNER) },
                        icon = {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = stringResource(R.string.nav_scanner)
                            )
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_scanner")
                    )

                    NavigationDrawerItem(
                        label = { Text(stringResource(R.string.nav_benchmark)) },
                        selected = currentScreen == AppScreen.BENCHMARK,
                        onClick = { navigateTo(AppScreen.BENCHMARK) },
                        icon = {
                            Icon(
                                imageVector = Icons.Default.Build,
                                contentDescription = stringResource(R.string.nav_benchmark)
                            )
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_benchmark")
                    )

                    NavigationDrawerItem(
                        label = { Text(stringResource(R.string.nav_guide)) },
                        selected = currentScreen == AppScreen.GUIDE,
                        onClick = { navigateTo(AppScreen.GUIDE) },
                        icon = {
                            Icon(
                                imageVector = Icons.Default.Info,
                                contentDescription = stringResource(R.string.nav_guide)
                            )
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_guide")
                    )

                    Spacer(Modifier.height(16.dp))
                }
            }
        ) {
            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing,
                topBar = {
                    TopAppBar(
                        navigationIcon = {
                            IconButton(
                                onClick = { scope.launch { drawerState.open() } },
                                modifier = Modifier
                                    .sizeIn(minWidth = 48.dp, minHeight = 48.dp)
                                    .testTag("drawer_menu_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Menu,
                                    contentDescription = stringResource(R.string.cd_open_drawer)
                                )
                            }
                        },
                        title = {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Image(
                                    painter = painterResource(id = R.drawable.ic_sakura_logo),
                                    contentDescription = "SakuraNet App Logo",
                                    modifier = Modifier
                                        .size(34.dp)
                                        .clip(RoundedCornerShape(8.dp))
                                        .testTag("app_header_logo")
                                )
                                Column {
                                    Text(
                                        text = stringResource(currentScreen.titleRes),
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Bold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = when (hasRoot) {
                                            null -> "SakuraNet • Checking adapter…"
                                            true -> "SakuraNet • Root + VPN-Safe"
                                            false -> "SakuraNet • VPN-Safe Socket"
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        },
                        actions = {
                            AssistChip(
                                onClick = { showConfigJsonDialog = true },
                                label = { Text(stringResource(R.string.action_view_json)) },
                                modifier = Modifier
                                    .padding(end = 8.dp)
                                    .testTag("view_json_button")
                            )
                        }
                    )
                },
                bottomBar = {
                    NavigationBar(
                        modifier = Modifier.testTag("bottom_nav_bar")
                    ) {
                        NavigationBarItem(
                            selected = currentScreen == AppScreen.HOME,
                            onClick = { currentScreen = AppScreen.HOME },
                            label = { Text(stringResource(R.string.nav_home)) },
                            icon = {
                                Icon(
                                    imageVector = Icons.Default.Home,
                                    contentDescription = stringResource(R.string.nav_home)
                                )
                            },
                            modifier = Modifier.testTag("nav_tab_dashboard")
                        )
                        NavigationBarItem(
                            selected = currentScreen == AppScreen.SETTINGS,
                            onClick = { currentScreen = AppScreen.SETTINGS },
                            label = { Text(stringResource(R.string.nav_settings)) },
                            icon = {
                                Icon(
                                    imageVector = Icons.Default.Settings,
                                    contentDescription = stringResource(R.string.nav_settings)
                                )
                            },
                            modifier = Modifier.testTag("nav_tab_settings")
                        )
                        NavigationBarItem(
                            selected = currentScreen == AppScreen.LOGS,
                            onClick = { currentScreen = AppScreen.LOGS },
                            label = { Text(stringResource(R.string.nav_logs)) },
                            icon = {
                                BadgedBox(
                                    badge = {
                                        if (logLines.isNotEmpty()) {
                                            Badge { Text(logLines.size.coerceAtMost(99).toString()) }
                                        }
                                    }
                                ) {
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.List,
                                        contentDescription = stringResource(R.string.nav_logs)
                                    )
                                }
                            },
                            modifier = Modifier.testTag("nav_tab_logs")
                        )
                    }
                }
            ) { innerPadding ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    contentAlignment = Alignment.TopCenter
                ) {
                    Column(
                        modifier = Modifier
                            .widthIn(max = 680.dp)
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        when (currentScreen) {
                            AppScreen.HOME -> {
                                // ============================================================
                                // HOME SCREEN: CLEAN CATEGORIZED QUICK-CONNECT VIEW
                                // ============================================================
                                if (!deviceNetStatus.hasInternet) {
                                    NoInternetWarningBanner(
                                        isProxyRunning = running,
                                        transportLabel = deviceNetStatus.transportLabel
                                    )
                                }

                                // 1. Live Service Status & Traffic Monitor Card
                                SniServiceStatusIndicator(
                                    isRunning = running,
                                    wakeLockHeld = wakeLockHeld,
                                    deviceNetStatus = deviceNetStatus,
                                    listenPort = listenPort,
                                    connectIp = connectIp,
                                    connectPort = connectPort,
                                    fakeSni = fakeSni,
                                    method = "$method ($fragmentStrategy)",
                                    onCopyEndpoint = {
                                        copyToClipboard(context, "Local Proxy", "127.0.0.1:$listenPort")
                                    }
                                )

                                // 2. Primary Start / Stop Action Buttons
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                                ) {
                                    Button(
                                        enabled = !running && connectIp.isNotBlank() && fakeSni.isNotBlank(),
                                        modifier = Modifier
                                            .weight(1f)
                                            .heightIn(min = 50.dp)
                                            .testTag("start_service_button"),
                                        onClick = {
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                                                ContextCompat.checkSelfPermission(
                                                    context,
                                                    Manifest.permission.POST_NOTIFICATIONS
                                                ) != PackageManager.PERMISSION_GRANTED
                                            ) {
                                                notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                            } else {
                                                startProxyAction()
                                            }
                                        }
                                    ) {
                                        Text(
                                            text = stringResource(R.string.action_start_proxy),
                                            fontWeight = FontWeight.Bold
                                        )
                                    }

                                    OutlinedButton(
                                        enabled = running,
                                        modifier = Modifier
                                            .weight(1f)
                                            .heightIn(min = 50.dp)
                                            .testTag("stop_service_button"),
                                        onClick = {
                                            SniSpoofService.stop(context)
                                        }
                                    ) {
                                        Text(
                                            text = stringResource(R.string.action_stop_proxy),
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }

                                // 3. Saved Profiles Strip (Compact Card)
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(14.dp),
                                    colors = CardDefaults.cardColors(
                                        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                                    )
                                ) {
                                    Column(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(horizontal = 12.dp, vertical = 10.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "Quick Server Presets",
                                                style = MaterialTheme.typography.labelLarge,
                                                fontWeight = FontWeight.Bold
                                            )
                                            TextButton(
                                                onClick = { showSaveProfileDialog = true },
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                                                modifier = Modifier
                                                    .heightIn(min = 32.dp)
                                                    .testTag("save_profile_button")
                                            ) {
                                                Text("+ Save Current", style = MaterialTheme.typography.labelSmall)
                                            }
                                        }

                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .horizontalScroll(rememberScrollState()),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            profiles.forEach { prof ->
                                                val selected = activeProfileId == prof.id
                                                InputChip(
                                                    selected = selected,
                                                    onClick = {
                                                        activeProfileId = prof.id
                                                        connectIp = prof.config.connectIp
                                                        connectPort = prof.config.connectPort.toString()
                                                        listenPort = prof.config.listenPort.toString()
                                                        fakeSni = prof.config.fakeSni
                                                        method = prof.config.method
                                                        fragmentStrategy = prof.config.fragmentStrategy
                                                        fragmentDelayMs = prof.config.fragmentDelayMs.toString()
                                                        handshakeTimeoutMs = prof.config.handshakeTimeoutMs.toString()
                                                        connectTimeoutMs = prof.config.connectTimeoutMs.toString()
                                                        logLevel = prof.config.logLevel
                                                        engineMode = prof.config.engineMode
                                                        bypassVpnTun = prof.config.bypassVpnTun
                                                        decoyTtl = prof.config.decoyTtl.toString()
                                                        chunkSize = prof.config.chunkSize.toString()
                                                        fragmentCount = prof.config.fragmentCount.toString()
                                                        tcpNoDelay = prof.config.tcpNoDelay
                                                        byteRangeSpec = prof.config.byteRangeSpec
                                                        delayRangeSpec = prof.config.delayRangeSpec
                                                        sniOffsetShift = prof.config.sniOffsetShift.toString()
                                                        sniCaseObfuscation = prof.config.sniCaseObfuscation
                                                        tlsPaddingSize = prof.config.tlsPaddingSize.toString()
                                                        greaseObfuscation = prof.config.greaseObfuscation
                                                        tlsRecordVersionCap = prof.config.tlsRecordVersionCap
                                                        decoyPayloadMode = prof.config.decoyPayloadMode
                                                        decoyRepeats = prof.config.decoyRepeats.toString()
                                                    },
                                                    label = { Text(prof.name, style = MaterialTheme.typography.labelSmall) },
                                                    trailingIcon = if (prof.id.startsWith("prof_")) {
                                                        {
                                                            Text(
                                                                text = "×",
                                                                fontWeight = FontWeight.Bold,
                                                                modifier = Modifier
                                                                    .padding(start = 4.dp)
                                                                    .clickable {
                                                                        profiles = ProfileStore.deleteProfile(context, prof.id)
                                                                        if (activeProfileId == prof.id) activeProfileId = null
                                                                    }
                                                            )
                                                        }
                                                    } else {
                                                        null
                                                    }
                                                )
                                            }
                                        }
                                    }
                                }

                                // 4. STEP 1 CARD: Target Server & Ports
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
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            Surface(
                                                shape = RoundedCornerShape(6.dp),
                                                color = MaterialTheme.colorScheme.primaryContainer
                                            ) {
                                                Text(
                                                    text = "STEP 1",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.Bold,
                                                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                            Text(
                                                text = "Target Server & Ports",
                                                style = MaterialTheme.typography.titleSmall,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }

                                        OutlinedTextField(
                                            value = connectIp,
                                            onValueChange = {
                                                connectIp = it
                                                dnsError = null
                                            },
                                            label = { Text("Target Server (IP or Domain)") },
                                            placeholder = { Text("172.66.129.89") },
                                            singleLine = true,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .testTag("connect_ip_input")
                                        )

                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            OutlinedTextField(
                                                value = connectPort,
                                                onValueChange = { connectPort = it.filter(Char::isDigit) },
                                                label = { Text("Server Port") },
                                                singleLine = true,
                                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .testTag("connect_port_input")
                                            )
                                            OutlinedTextField(
                                                value = listenPort,
                                                onValueChange = { listenPort = it.filter(Char::isDigit) },
                                                label = { Text("Local Port (v2ray)") },
                                                singleLine = true,
                                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .testTag("listen_port_input")
                                            )
                                        }

                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            OutlinedButton(
                                                enabled = !isResolvingDns && connectIp.isNotBlank(),
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .heightIn(min = 42.dp)
                                                    .testTag("resolve_dns_button"),
                                                onClick = {
                                                    isResolvingDns = true
                                                    dnsError = null
                                                    scope.launch {
                                                        val res = NetworkTools.resolveDomainIps(connectIp, context)
                                                        isResolvingDns = false
                                                        res.onSuccess { ips ->
                                                            resolvedIps = ips
                                                            if (ips.size == 1) connectIp = ips.first()
                                                        }.onFailure { err ->
                                                            dnsError = err.message ?: "DNS lookup failed"
                                                            resolvedIps = emptyList()
                                                        }
                                                    }
                                                }
                                            ) {
                                                Text(if (isResolvingDns) "Resolving…" else stringResource(R.string.action_resolve_dns))
                                            }

                                            OutlinedButton(
                                                enabled = !isTestingTcp && connectIp.isNotBlank(),
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .heightIn(min = 42.dp)
                                                    .testTag("tcp_ping_button"),
                                                onClick = {
                                                    isTestingTcp = true
                                                    scope.launch {
                                                        val portNum = connectPort.toIntOrNull() ?: 443
                                                        val res = NetworkTools.testTcpLatency(connectIp, portNum, 3500, context)
                                                        tcpProbeResult = res
                                                        isTestingTcp = false
                                                        LogBus.push("[ping] ${res.host}:${res.port} -> ${res.detail}")
                                                    }
                                                }
                                            ) {
                                                Text(if (isTestingTcp) "Testing…" else stringResource(R.string.action_tcp_ping))
                                            }
                                        }

                                        dnsError?.let { err ->
                                            Text(
                                                text = err,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.error
                                            )
                                        }

                                        if (resolvedIps.isNotEmpty()) {
                                            Text(
                                                text = "Discovered Edge IPs (tap to use):",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            FlowRow(
                                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                                verticalArrangement = Arrangement.spacedBy(6.dp)
                                            ) {
                                                resolvedIps.forEach { ip ->
                                                    SuggestionChip(
                                                        onClick = { connectIp = ip },
                                                        label = { Text(ip, fontFamily = FontFamily.Monospace) }
                                                    )
                                                }
                                            }
                                        }

                                        tcpProbeResult?.let { probe ->
                                            Surface(
                                                shape = RoundedCornerShape(10.dp),
                                                color = if (probe.reachable) Color(0xFFE7F6EE) else MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.65f),
                                                modifier = Modifier.fillMaxWidth()
                                            ) {
                                                Text(
                                                    text = "${probe.host}:${probe.port} • ${probe.detail}",
                                                    style = MaterialTheme.typography.bodySmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = if (probe.reachable) Color(0xFF0E4F30) else MaterialTheme.colorScheme.onErrorContainer,
                                                    modifier = Modifier.padding(10.dp)
                                                )
                                            }
                                        }
                                    }
                                }

                                // 5. STEP 2 CARD: Clean SNI & Bypass Method
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
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                                            ) {
                                                Surface(
                                                    shape = RoundedCornerShape(6.dp),
                                                    color = MaterialTheme.colorScheme.primaryContainer
                                                ) {
                                                    Text(
                                                        text = "STEP 2",
                                                        style = MaterialTheme.typography.labelSmall,
                                                        fontWeight = FontWeight.Bold,
                                                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                    )
                                                }
                                                Text(
                                                    text = "Clean SNI & Bypass Mode",
                                                    style = MaterialTheme.typography.titleSmall,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }

                                            TextButton(
                                                onClick = { currentScreen = AppScreen.SCANNER },
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                                                modifier = Modifier
                                                    .heightIn(min = 32.dp)
                                                    .testTag("open_sni_scanner_button")
                                            ) {
                                                Text("Scan SNIs ›", style = MaterialTheme.typography.labelSmall)
                                            }
                                        }

                                        OutlinedTextField(
                                            value = fakeSni,
                                            onValueChange = { fakeSni = it },
                                            label = { Text("Fake SNI (Clean Unblocked Domain)") },
                                            singleLine = true,
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .testTag("fake_sni_input")
                                        )

                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .horizontalScroll(rememberScrollState()),
                                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                                        ) {
                                            SpoofConfig.DEFAULT_CLEAN_SNIS.forEach { preset ->
                                                FilterChip(
                                                    selected = fakeSni.equals(preset, ignoreCase = true),
                                                    onClick = { fakeSni = preset },
                                                    label = { Text(preset, style = MaterialTheme.typography.labelSmall) }
                                                )
                                            }
                                        }

                                        HorizontalDivider(modifier = Modifier.padding(vertical = 2.dp))

                                        // Bypass Method Header + Auto-Benchmark shortcut
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    text = "Bypass Method:",
                                                    style = MaterialTheme.typography.labelLarge,
                                                    fontWeight = FontWeight.SemiBold
                                                )
                                                val activeMeta = SpoofConfig.METHOD_METAS.find { it.id == method }
                                                if (activeMeta != null) {
                                                    Text(
                                                        text = "${activeMeta.title} (${activeMeta.badge})",
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = MaterialTheme.colorScheme.primary,
                                                        fontWeight = FontWeight.Medium
                                                    )
                                                }
                                            }

                                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                                FilledTonalButton(
                                                    onClick = { currentScreen = AppScreen.BENCHMARK },
                                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                                    modifier = Modifier
                                                        .heightIn(min = 34.dp)
                                                        .testTag("open_benchmark_button")
                                                ) {
                                                    Text("⚡ Auto-Test", style = MaterialTheme.typography.labelSmall)
                                                }
                                                OutlinedButton(
                                                    onClick = { showMethodDetails = !showMethodDetails },
                                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                                    modifier = Modifier.heightIn(min = 34.dp)
                                                ) {
                                                    Text(
                                                        text = if (showMethodDetails) "Compact" else "Details",
                                                        style = MaterialTheme.typography.labelSmall
                                                    )
                                                }
                                            }
                                        }

                                        // Clean Flow Chip Selector (Always visible & keeps all method_option_<id> testTags)
                                        if (!showMethodDetails) {
                                            FlowRow(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                                verticalArrangement = Arrangement.spacedBy(6.dp)
                                            ) {
                                                SpoofConfig.METHOD_METAS.forEach { meta ->
                                                    val isSelected = method == meta.id
                                                    FilterChip(
                                                        selected = isSelected,
                                                        onClick = { method = meta.id },
                                                        label = {
                                                            Text(
                                                                text = meta.title,
                                                                style = MaterialTheme.typography.labelSmall,
                                                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                                            )
                                                        },
                                                        modifier = Modifier.testTag("method_option_${meta.id}")
                                                    )
                                                }
                                            }
                                        } else {
                                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                                SpoofConfig.METHOD_METAS.forEach { meta ->
                                                    val isSelected = method == meta.id
                                                    Surface(
                                                        shape = RoundedCornerShape(12.dp),
                                                        color = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f) else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                                                        border = BorderStroke(
                                                            width = if (isSelected) 1.5.dp else 1.dp,
                                                            color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f)
                                                        ),
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .clip(RoundedCornerShape(12.dp))
                                                            .clickable { method = meta.id }
                                                            .testTag("method_option_${meta.id}")
                                                    ) {
                                                        Column(
                                                            modifier = Modifier
                                                                .fillMaxWidth()
                                                                .padding(horizontal = 12.dp, vertical = 8.dp)
                                                        ) {
                                                            Row(
                                                                modifier = Modifier.fillMaxWidth(),
                                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                                verticalAlignment = Alignment.CenterVertically
                                                            ) {
                                                                Row(
                                                                    verticalAlignment = Alignment.CenterVertically,
                                                                    modifier = Modifier.weight(1f)
                                                                ) {
                                                                    RadioButton(
                                                                        selected = isSelected,
                                                                        onClick = { method = meta.id },
                                                                        modifier = Modifier.size(20.dp)
                                                                    )
                                                                    Spacer(Modifier.width(8.dp))
                                                                    Text(
                                                                        text = meta.title,
                                                                        style = MaterialTheme.typography.bodyMedium,
                                                                        fontWeight = FontWeight.Bold
                                                                    )
                                                                }
                                                                Surface(
                                                                    shape = RoundedCornerShape(50),
                                                                    color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant
                                                                ) {
                                                                    Text(
                                                                        text = meta.badge,
                                                                        style = MaterialTheme.typography.labelSmall,
                                                                        color = if (isSelected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                                                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                                                    )
                                                                }
                                                            }
                                                            Spacer(Modifier.height(2.dp))
                                                            Text(
                                                                text = meta.description,
                                                                style = MaterialTheme.typography.bodySmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                                            )
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // 6. STEP 3 CARD: v2rayNG VPN Coexistence & Background Keep-Alive
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .testTag("v2ray_keepalive_card"),
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
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Row(
                                                    verticalAlignment = Alignment.CenterVertically,
                                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                                ) {
                                                    Surface(
                                                        shape = RoundedCornerShape(6.dp),
                                                        color = MaterialTheme.colorScheme.secondary
                                                    ) {
                                                        Text(
                                                            text = "STEP 3",
                                                            style = MaterialTheme.typography.labelSmall,
                                                            fontWeight = FontWeight.Bold,
                                                            color = MaterialTheme.colorScheme.onSecondary,
                                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                        )
                                                    }
                                                    Text(
                                                        text = "v2rayNG VPN Coexistence",
                                                        style = MaterialTheme.typography.titleSmall,
                                                        fontWeight = FontWeight.Bold
                                                    )
                                                }
                                                Spacer(Modifier.height(4.dp))
                                                Text(
                                                    text = if (deviceNetStatus.vpnActive) {
                                                        "VPN Active (tun0) • Outbound pinned to ${deviceNetStatus.physicalInterface}"
                                                    } else {
                                                        "Physical Socket Ready: ${deviceNetStatus.physicalInterface} (Stays alive with v2rayNG)"
                                                    },
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }
                                            Switch(
                                                checked = bypassVpnTun,
                                                onCheckedChange = { bypassVpnTun = it },
                                                modifier = Modifier.testTag("dashboard_bypass_vpn_switch")
                                            )
                                        }

                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            OutlinedButton(
                                                onClick = {
                                                    copyToClipboard(context, "Local Proxy", "127.0.0.1:$listenPort")
                                                },
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .heightIn(min = 40.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                            ) {
                                                Text(
                                                    text = "Copy 127.0.0.1:$listenPort",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                            }

                                            OutlinedButton(
                                                onClick = {
                                                    copyToClipboard(context, "Package Name", context.packageName)
                                                },
                                                modifier = Modifier
                                                    .weight(1f)
                                                    .heightIn(min = 40.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                            ) {
                                                Text(
                                                    text = "Copy App ID (Bypass)",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                            }
                                        }

                                        if (!batteryUnrestricted) {
                                            Button(
                                                onClick = {
                                                    requestIgnoreBatteryOptimizations(context, batteryOptLauncher)
                                                },
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .heightIn(min = 42.dp)
                                                    .testTag("keep_alive_battery_button"),
                                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                                            ) {
                                                Text(
                                                    text = "🔋 Enable Unconditional Background Keep-Alive",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                        }
                                    }
                                }
                            }

                            AppScreen.SETTINGS -> {
                                // ============================================================
                                // SETTINGS SCREEN: CATEGORIZED SETTINGS & MANUAL APK EXPORT
                                // ============================================================
                                SettingsScreen(
                                    context = context,
                                    engineMode = engineMode,
                                    onEngineModeChange = { engineMode = it },
                                    bypassVpnTun = bypassVpnTun,
                                    onBypassVpnTunChange = { bypassVpnTun = it },
                                    hasRoot = hasRoot,
                                    listenPort = listenPort,
                                    onListenPortChange = { listenPort = it.filter(Char::isDigit) },
                                    fragmentStrategy = fragmentStrategy,
                                    onFragmentStrategyChange = { fragmentStrategy = it },
                                    byteRangeSpec = byteRangeSpec,
                                    onByteRangeSpecChange = { byteRangeSpec = it },
                                    delayRangeSpec = delayRangeSpec,
                                    onDelayRangeSpecChange = { delayRangeSpec = it },
                                    sniOffsetShift = sniOffsetShift,
                                    onSniOffsetShiftChange = { sniOffsetShift = it.filter(Char::isDigit) },
                                    chunkSize = chunkSize,
                                    onChunkSizeChange = { chunkSize = it.filter(Char::isDigit) },
                                    fragmentCount = fragmentCount,
                                    onFragmentCountChange = { fragmentCount = it.filter(Char::isDigit) },
                                    fragmentDelayMs = fragmentDelayMs,
                                    onFragmentDelayMsChange = { fragmentDelayMs = it.filter(Char::isDigit) },
                                    connectTimeoutMs = connectTimeoutMs,
                                    onConnectTimeoutMsChange = { connectTimeoutMs = it.filter(Char::isDigit) },
                                    handshakeTimeoutMs = handshakeTimeoutMs,
                                    onHandshakeTimeoutMsChange = { handshakeTimeoutMs = it.filter(Char::isDigit) },
                                    sniCaseObfuscation = sniCaseObfuscation,
                                    onSniCaseObfuscationChange = { sniCaseObfuscation = it },
                                    tlsPaddingSize = tlsPaddingSize,
                                    onTlsPaddingSizeChange = { tlsPaddingSize = it.filter(Char::isDigit) },
                                    greaseObfuscation = greaseObfuscation,
                                    onGreaseObfuscationChange = { greaseObfuscation = it },
                                    tlsRecordVersionCap = tlsRecordVersionCap,
                                    onTlsRecordVersionCapChange = { tlsRecordVersionCap = it },
                                    decoyTtl = decoyTtl,
                                    onDecoyTtlChange = { decoyTtl = it.filter(Char::isDigit) },
                                    decoyPayloadMode = decoyPayloadMode,
                                    onDecoyPayloadModeChange = { decoyPayloadMode = it },
                                    decoyRepeats = decoyRepeats,
                                    onDecoyRepeatsChange = { decoyRepeats = it.filter(Char::isDigit) },
                                    tcpNoDelay = tcpNoDelay,
                                    onTcpNoDelayChange = { tcpNoDelay = it },
                                    logLevel = logLevel,
                                    onLogLevelChange = { logLevel = it },
                                    deviceNetStatus = deviceNetStatus,
                                    apkExportStatus = apkExportStatus,
                                    onSaveApkToDownloads = { saveApkToDownloadsAction() },
                                    onSaveApkAs = { createApkDocLauncher.launch(ApkExporter.DEFAULT_APK_NAME) },
                                    onResetDefaults = {
                                        val def = SpoofConfig()
                                        listenPort = def.listenPort.toString()
                                        connectPort = def.connectPort.toString()
                                        method = def.method
                                        fragmentStrategy = def.fragmentStrategy
                                        fragmentDelayMs = def.fragmentDelayMs.toString()
                                        chunkSize = def.chunkSize.toString()
                                        fragmentCount = def.fragmentCount.toString()
                                        byteRangeSpec = def.byteRangeSpec
                                        delayRangeSpec = def.delayRangeSpec
                                        sniOffsetShift = def.sniOffsetShift.toString()
                                        sniCaseObfuscation = def.sniCaseObfuscation
                                        tlsPaddingSize = def.tlsPaddingSize.toString()
                                        greaseObfuscation = def.greaseObfuscation
                                        tlsRecordVersionCap = def.tlsRecordVersionCap
                                        decoyPayloadMode = def.decoyPayloadMode
                                        decoyTtl = def.decoyTtl.toString()
                                        decoyRepeats = def.decoyRepeats.toString()
                                        tcpNoDelay = def.tcpNoDelay
                                        bypassVpnTun = true
                                        engineMode = "vpn_safe_kotlin"
                                    }
                                )
                            }

                            AppScreen.LOGS -> {
                                // ============================================================
                                // LOGS SCREEN: DEDICATED REAL-TIME SERVICE LOG STREAM
                                // ============================================================
                                LiveLogsTab(
                                    logLines = logLines,
                                    isServiceRunning = running,
                                    onClearLogs = { LogBus.clear() }
                                )
                            }

                            AppScreen.SCANNER -> {
                                // ============================================================
                                // CLEAN SNI SCANNER SCREEN
                                // ============================================================
                                SniScannerTab(
                                    connectIp = connectIp,
                                    connectPort = connectPort.toIntOrNull() ?: 443,
                                    listenPort = listenPort.toIntOrNull() ?: 40443,
                                    currentFakeSni = fakeSni,
                                    onSelectSni = { chosenSni ->
                                        fakeSni = chosenSni
                                        currentScreen = AppScreen.HOME
                                    }
                                )
                            }

                            AppScreen.BENCHMARK -> {
                                // ============================================================
                                // METHOD BENCHMARK / AUTO-TESTER SCREEN
                                // ============================================================
                                MethodBenchmarkScreen(
                                    context = context,
                                    targetIp = connectIp,
                                    targetPort = connectPort.toIntOrNull() ?: 443,
                                    fakeSni = fakeSni,
                                    currentMethod = method,
                                    currentStrategy = fragmentStrategy,
                                    onApplyMethod = { newMethod, newStrategy, newByteRange ->
                                        method = newMethod
                                        fragmentStrategy = newStrategy
                                        if (newByteRange.isNotBlank()) {
                                            byteRangeSpec = newByteRange
                                        }
                                        currentScreen = AppScreen.HOME
                                    }
                                )
                            }

                            AppScreen.GUIDE -> {
                                // ============================================================
                                // COMPREHENSIVE GUIDE & TUTORIALS SCREEN
                                // ============================================================
                                GuideScreen(
                                    context = context,
                                    listenPort = listenPort,
                                    onNavigateToSettings = { currentScreen = AppScreen.SETTINGS },
                                    onNavigateToBenchmark = { currentScreen = AppScreen.BENCHMARK }
                                )
                            }
                        }
                    }
                }
            }
        }

        if (showConfigJsonDialog) {
            ConfigJsonDialog(
                config = currentSpoofConfig,
                onDismiss = { showConfigJsonDialog = false }
            )
        }

        if (showSaveProfileDialog) {
            SaveProfileDialog(
                defaultName = "${connectIp.ifBlank { "Edge" }} ($method/$fragmentStrategy)",
                onSave = { name ->
                    profiles = ProfileStore.saveProfile(context, name, currentSpoofConfig)
                    showSaveProfileDialog = false
                },
                onDismiss = { showSaveProfileDialog = false }
            )
        }
    }
}

fun isBatteryOptimizationIgnored(context: android.content.Context): Boolean {
    return try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = context.getSystemService(android.content.Context.POWER_SERVICE) as? android.os.PowerManager
            pm?.isIgnoringBatteryOptimizations(context.packageName) ?: true
        } else {
            true
        }
    } catch (_: Exception) {
        true
    }
}

fun requestIgnoreBatteryOptimizations(
    context: android.content.Context,
    launcher: androidx.activity.result.ActivityResultLauncher<android.content.Intent>
) {
    try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val intent = android.content.Intent(
                android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                android.net.Uri.parse("package:${context.packageName}")
            )
            launcher.launch(intent)
        }
    } catch (_: Exception) {
        runCatching {
            val fallback = android.content.Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            launcher.launch(fallback)
        }
    }
}
