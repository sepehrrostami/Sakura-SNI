package com.sakuranet.snispoof

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.Process as AndroidProcess
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger

/**
 * Persistent foreground service that owns the lifetime of the SNI spoofing proxy
 * (either the built-in VPN-Safe [SakuraProxyEngine] or the `sakura-sni` binary).
 * - Uses ForegroundServiceType (DATA_SYNC | SPECIAL_USE on Android 14+) + FOREGROUND_SERVICE_IMMEDIATE.
 * - Acquires both a CPU PARTIAL_WAKE_LOCK and a low-latency WifiLock so background sockets
 *   are never throttled or suspended when switching to v2rayNG.
 * - Pins the underlying physical Wi-Fi/Cellular [android.net.Network] via [NetworkTools]
 *   and automatically re-applies bypass routing the instant `tun0` VPN starts.
 */
class SniSpoofService : Service() {

    @Volatile
    private var proc: Process? = null
    @Volatile
    private var kotlinEngine: SakuraProxyEngine? = null
    @Volatile
    private var currentUseRoot: Boolean = false
    @Volatile
    private var userRequestedStop: Boolean = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var currentSummary: String = "Local SNI proxy active"
    private var serviceStartedAtMs: Long = 0L
    @Volatile
    private var lastNotificationUpdateMs: Long = 0L
    @Volatile
    private var watchdogRunning: Boolean = false

    /** Serializes engine/process start and teardown done on background threads. Never taken on the main thread. */
    private val spoofLock = Any()
    /** Bumped by every start and stop; a starter thread that is no longer current discards what it built. */
    private val startGeneration = AtomicInteger(0)
    /** Starter threads still running (su prompt, route setup, launch) — the watchdog must not race them. */
    private val pendingStarts = AtomicInteger(0)

    private val vpnTransitionListener: (Boolean, String) -> Unit = { vpnActive, physIface ->
        if (!userRequestedStop && LogBus.isRunning()) {
            val activeCfg = ProfileStore.loadActiveConfig(this)
            if (vpnActive) {
                LogBus.push(
                    "[net] VPN tunnel (tun0) detected active — pinning outbound traffic to ${physIface.ifBlank { "physical network" }}"
                )
                if (currentUseRoot && activeCfg.bypassVpnTun && activeCfg.connectIp.isNotBlank()) {
                    Thread {
                        RootShell.setupVpnBypassRules(
                            connectIp = activeCfg.connectIp,
                            physicalIface = physIface,
                            appUid = AndroidProcess.myUid(),
                            onLine = { LogBus.push(it) }
                        )
                    }.apply { isDaemon = true }.start()
                }
            } else {
                LogBus.push("[net] VPN tunnel (tun0) disconnected — physical interface: ${physIface.ifBlank { "default" }}")
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        NetworkTools.ensurePhysicalNetworkTracker(applicationContext)
        NetworkTools.addVpnStateListener(vpnTransitionListener)
        startWatchdogIfNeeded()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        NetworkTools.ensurePhysicalNetworkTracker(applicationContext)
        when (intent?.action) {
            ACTION_STOP -> {
                userRequestedStop = true
                clearSavedSession()
                stopSpoof()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                userRequestedStop = false
                val restored = loadSavedSession()
                if (restored != null) {
                    LogBus.push("[service] Restarting proxy from notification action...")
                    currentSummary = restored.summary
                    if (serviceStartedAtMs == 0L) serviceStartedAtMs = System.currentTimeMillis()
                    startForegroundSafely(buildNotification("Restarting (${restored.method} mode)..."))
                    startSpoof(restored.binPath, restored.configPath, restored.useRoot, restored.method)
                }
                return START_STICKY
            }
            ACTION_ENSURE_ALIVE -> {
                val restored = loadSavedSession()
                if (restored != null && !userRequestedStop) {
                    val engineAlive = pendingStarts.get() > 0 ||
                        kotlinEngine?.isListenerHealthy() == true || proc?.isAlive == true
                    if (!engineAlive) {
                        currentSummary = restored.summary
                        if (serviceStartedAtMs == 0L) serviceStartedAtMs = System.currentTimeMillis()
                        startForegroundSafely(buildNotification("Active (${restored.method} mode)"))
                        startSpoof(restored.binPath, restored.configPath, restored.useRoot, restored.method)
                    } else {
                        LogBus.setRunning(true)
                        LogBus.setWakeLockHeld(wakeLock?.isHeld == true)
                    }
                }
                return START_STICKY
            }
            else -> {
                userRequestedStop = false
                val cfg = intent?.getStringExtra(EXTRA_CONFIG_PATH)
                val bin = intent?.getStringExtra(EXTRA_BIN_PATH)
                val useRoot = intent?.getBooleanExtra(EXTRA_USE_ROOT, false)
                val method = intent?.getStringExtra(EXTRA_METHOD)
                val summary = intent?.getStringExtra(EXTRA_ROUTE_SUMMARY)

                if (cfg != null && bin != null) {
                    val resolvedRoot = useRoot ?: false
                    val resolvedMethod = method ?: "combined"
                    val resolvedSummary = summary ?: "Mode: $resolvedMethod"
                    currentSummary = resolvedSummary
                    serviceStartedAtMs = System.currentTimeMillis()
                    saveSession(bin, cfg, resolvedRoot, resolvedMethod, resolvedSummary)
                    startForegroundSafely(buildNotification("Starting ($resolvedMethod mode)..."))
                    startSpoof(bin, cfg, resolvedRoot, resolvedMethod)
                } else {
                    val restored = loadSavedSession()
                    if (restored != null && File(restored.configPath).exists()) {
                        currentSummary = restored.summary
                        serviceStartedAtMs = System.currentTimeMillis()
                        startForegroundSafely(buildNotification("Restored (${restored.method} mode)"))
                        LogBus.push("[service] Restored persistent proxy session in background")
                        startSpoof(restored.binPath, restored.configPath, restored.useRoot, restored.method)
                    } else {
                        stopSelf()
                        return START_NOT_STICKY
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun startWatchdogIfNeeded() {
        if (watchdogRunning) return
        watchdogRunning = true
        Thread {
            while (watchdogRunning) {
                try {
                    Thread.sleep(3500)
                    if (!watchdogRunning || userRequestedStop) continue
                    // A start is still in flight (su prompt, route setup, launch): don't race it,
                    // otherwise two engines fight over the listen port.
                    if (pendingStarts.get() > 0) continue
                    val saved = loadSavedSession() ?: continue
                    NetworkTools.ensurePhysicalNetworkTracker(applicationContext)

                    // Judge health by what is actually running, not by the engine mode currently
                    // saved in the (possibly mid-edit) settings.
                    val isHealthy = kotlinEngine?.isListenerHealthy() == true || proc?.isAlive == true

                    if (!isHealthy && !userRequestedStop) {
                        LogBus.push("[service] Watchdog: Local listener interrupted during network/VPN transition — auto-healing...")
                        startSpoof(saved.binPath, saved.configPath, saved.useRoot, saved.method)
                    }
                } catch (_: InterruptedException) {
                    break
                } catch (_: Exception) {
                }
            }
        }.apply { isDaemon = true }.start()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if ((proc != null || kotlinEngine?.isRunning() == true) && LogBus.isRunning()) {
            LogBus.push("[service] App swiped from Recents — foreground proxy continues in background")
            updateNotification("Running in background • $currentSummary", force = true)
        }
    }

    private fun acquireWakeLock() {
        try {
            if (wakeLock?.isHeld != true) {
                val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
                if (pm != null) {
                    wakeLock = pm.newWakeLock(
                        PowerManager.PARTIAL_WAKE_LOCK,
                        "SakuraNet::SniProxyWakeLock"
                    ).apply {
                        setReferenceCounted(false)
                        acquire()
                    }
                }
            }
            if (wifiLock?.isHeld != true) {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                if (wm != null) {
                    val lockMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    } else {
                        @Suppress("DEPRECATION")
                        WifiManager.WIFI_MODE_FULL_HIGH_PERF
                    }
                    wifiLock = wm.createWifiLock(lockMode, "SakuraNet::SniProxyWifiLock").apply {
                        setReferenceCounted(false)
                        acquire()
                    }
                }
            }
            LogBus.setWakeLockHeld(true)
        } catch (e: Exception) {
            LogBus.push("[warn] Could not acquire WakeLock/WifiLock: ${e.message}")
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (_: Exception) {
        } finally {
            wakeLock = null
        }
        try {
            if (wifiLock?.isHeld == true) {
                wifiLock?.release()
            }
        } catch (_: Exception) {
        } finally {
            wifiLock = null
            LogBus.setWakeLockHeld(false)
        }
    }

    private fun startForegroundSafely(notification: Notification) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                try {
                    startForeground(
                        NOTIF_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    )
                } catch (_: Exception) {
                    startForeground(
                        NOTIF_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    )
                }
            } else {
                startForeground(NOTIF_ID, notification)
            }
        } catch (e: Exception) {
            LogBus.push("[warn] Foreground notification warning: ${e.message}")
        }
    }

    /**
     * Starts (or restarts) the proxy. Can be called from the main thread, the watchdog and the VPN
     * listener. Everything slow (su check, route setup, binary launch) runs on a starter thread,
     * serialized by [spoofLock]; [startGeneration] lets a superseded starter throw away what it
     * built instead of leaving a second engine holding the port.
     */
    private fun startSpoof(binPath: String, configPath: String, useRoot: Boolean, method: String) {
        val gen = startGeneration.incrementAndGet()
        pendingStarts.incrementAndGet()

        currentUseRoot = useRoot
        acquireWakeLock()
        NetworkTools.ensurePhysicalNetworkTracker(applicationContext)

        val activeConfig = ProfileStore.loadActiveConfig(this)
        val wantsNative = activeConfig.engineMode == "native_binary"

        LogBus.setRunning(true)
        updateNotification("Listening • $currentSummary", force = true)

        Thread {
            try {
                val hasRootAccess = useRoot || RootShell.isRootAvailable()
                if (gen != startGeneration.get()) return@Thread
                currentUseRoot = hasRootAccess

                synchronized(spoofLock) {
                    if (gen != startGeneration.get() || userRequestedStop) return@Thread

                    // Tear down whatever an earlier start left running — it may have been assigned
                    // after this start was requested, so this must happen under the lock.
                    stopRunningInstancesLocked()

                    // Free local port if any stale binary instance was holding it
                    RootShell.killExistingInstances(hasRootAccess, clearRoutes = false)

                    if (hasRootAccess && activeConfig.bypassVpnTun && activeConfig.connectIp.isNotBlank()) {
                        val physIface = NetworkTools.findPhysicalUnderlyingNetwork(this)?.second.orEmpty()
                        RootShell.setupVpnBypassRules(
                            connectIp = activeConfig.connectIp,
                            physicalIface = physIface,
                            appUid = AndroidProcess.myUid(),
                            onLine = { LogBus.push(it) }
                        )
                    }

                    val nativeBlocked = wantsNative && !hasRootAccess &&
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                    if (nativeBlocked) {
                        LogBus.push(
                            "[warn] Native sakura-sni needs root on Android 10+ — " +
                                "falling back to the VPN-Safe Kotlin engine"
                        )
                    }

                    if (!wantsNative || nativeBlocked) {
                        startKotlinEngineLocked(gen, activeConfig, hasRootAccess)
                    } else {
                        startNativeBinaryLocked(gen, binPath, configPath, hasRootAccess, method)
                    }
                }
            } catch (e: Exception) {
                LogBus.push("[error] Proxy start failed: ${e.message ?: e.javaClass.simpleName}")
            } finally {
                pendingStarts.decrementAndGet()
            }
        }.apply { isDaemon = true }.start()
    }

    /** Caller must hold [spoofLock]. */
    private fun stopRunningInstancesLocked() {
        val prevEngine = kotlinEngine
        kotlinEngine = null
        runCatching { prevEngine?.stop() }
        val prevProc = proc
        proc = null
        runCatching { prevProc?.destroy() }
    }

    /** True when [gen] is no longer the current start (a newer start or a stop happened). */
    private fun isSuperseded(gen: Int): Boolean = gen != startGeneration.get() || userRequestedStop

    /** Caller must hold [spoofLock]. */
    private fun startKotlinEngineLocked(gen: Int, activeConfig: SpoofConfig, hasRootAccess: Boolean) {
        val physNetDesc = NetworkTools.describePhysicalNetwork(this)
        LogBus.push(
            "[service] Starting VPN-Safe Multi-Method Engine (method=${activeConfig.method}, " +
                "strategy=${activeConfig.fragmentStrategy}, physNet=$physNetDesc)"
        )
        LogBus.push("[service] Persistent Foreground Service + CPU & Low-Latency Wi-Fi Lock active")

        var self: SakuraProxyEngine? = null
        val engine = SakuraProxyEngine(
            context = applicationContext,
            config = activeConfig,
            useRoot = hasRootAccess,
            onLine = { line ->
                LogBus.push(line)
                LogBus.recordProcessTraffic(line)
                updateNotification(line.take(80), force = false)
            },
            onExit = { code ->
                // Only forget the engine if it is still the current one; an old engine exiting
                // late must not wipe the reference to its replacement.
                val me = self
                if (me != null && kotlinEngine === me) {
                    kotlinEngine = null
                    LogBus.push("[service] VPN-Safe Proxy Engine exited (code=$code)")
                }
            }
        )
        self = engine
        if (!engine.start()) return // start() logged the bind error; the watchdog retries

        kotlinEngine = engine
        // stopSpoof() or a newer start may have run meanwhile: don't leave this engine orphaned.
        if (isSuperseded(gen)) {
            if (kotlinEngine === engine) kotlinEngine = null
            engine.stop()
        }
    }

    /** Caller must hold [spoofLock]. */
    private fun startNativeBinaryLocked(
        gen: Int,
        binPath: String,
        configPath: String,
        hasRootAccess: Boolean,
        method: String
    ) {
        val execMode = if (hasRootAccess) "root (su -c)" else "unprivileged direct process"
        LogBus.push("[service] Starting native sakura-sni in $method mode via $execMode")
        LogBus.push("[service] Persistent Foreground Service + CPU & Low-Latency Wi-Fi Lock active")
        val validBin = if (File(binPath).exists()) {
            binPath
        } else {
            RootShell.installBinary(this, filesDir).absolutePath
        }

        var started: Process? = null
        val startedProc = RootShell.runBinary(
            context = applicationContext,
            binPath = validBin,
            configPath = configPath,
            useRoot = hasRootAccess,
            onLine = { line ->
                LogBus.push(line)
                LogBus.recordProcessTraffic(line)
                updateNotification(line.take(80), force = false)
            },
            onExit = { exitCode ->
                val me = started
                if (me != null && proc === me) {
                    proc = null
                    LogBus.push("[service] sakura-sni process exited (code=$exitCode)")
                }
            }
        ) ?: return
        started = startedProc
        proc = startedProc

        if (isSuperseded(gen)) {
            if (proc === startedProc) proc = null
            runCatching { startedProc.destroy() }
            RootShell.killExistingInstances(hasRootAccess, clearRoutes = false)
        }
    }

    private fun stopSpoof() {
        // Invalidate any start still in flight before touching the references.
        val stopGen = startGeneration.incrementAndGet()

        val currentEngine = kotlinEngine
        kotlinEngine = null
        runCatching { currentEngine?.stop() }

        val current = proc
        val wasRoot = currentUseRoot
        proc = null
        runCatching { current?.destroy() }

        Thread {
            synchronized(spoofLock) {
                // The user already started again: that start cleans up after itself.
                if (startGeneration.get() != stopGen) return@Thread
                // A starter that was mid-flight has finished by now; drop anything it assigned
                // before noticing the stop, then kill root instances and clear the routes.
                stopRunningInstancesLocked()
                RootShell.killExistingInstances(wasRoot || currentUseRoot, clearRoutes = true)
            }
        }.apply { isDaemon = true }.start()
        releaseWakeLock()
        LogBus.setRunning(false)
        LogBus.push("[service] Proxy stopped by user")
    }

    override fun onDestroy() {
        watchdogRunning = false
        NetworkTools.removeVpnStateListener(vpnTransitionListener)
        if (userRequestedStop) {
            if (proc != null || kotlinEngine != null) {
                stopSpoof()
            } else {
                releaseWakeLock()
            }
        }
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SNI Spoof Persistent Proxy",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps the local SNI spoofing proxy alive in the background"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(latestLine: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPending = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val restartIntent = Intent(this, SniSpoofService::class.java).setAction(ACTION_RESTART)
        val restartPending = PendingIntent.getService(
            this,
            1,
            restartIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = Intent(this, SniSpoofService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val expandedBody = "$currentSummary\n$latestLine"
        val whenMs = if (serviceStartedAtMs > 0L) serviceStartedAtMs else System.currentTimeMillis()

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SakuraNet SNI Proxy Active")
            .setContentText(currentSummary)
            .setSubText("VPN-Safe Background Service")
            .setStyle(NotificationCompat.BigTextStyle().bigText(expandedBody))
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentIntent(openPending)
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setUsesChronometer(true)
            .setWhen(whenMs)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(0, "Restart", restartPending)
            .addAction(0, "Stop", stopPending)
            .build()
    }

    private fun updateNotification(latestLine: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force && (now - lastNotificationUpdateMs) < 2500L) {
            return
        }
        lastNotificationUpdateMs = now
        try {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr?.notify(NOTIF_ID, buildNotification(latestLine))
        } catch (_: Exception) {
        }
    }

    private data class SavedSession(
        val binPath: String,
        val configPath: String,
        val useRoot: Boolean,
        val method: String,
        val summary: String
    )

    private fun saveSession(binPath: String, configPath: String, useRoot: Boolean, method: String, summary: String) {
        getSharedPreferences(SESSION_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean("active", true)
            .putString("binPath", binPath)
            .putString("configPath", configPath)
            .putBoolean("useRoot", useRoot)
            .putString("method", method)
            .putString("summary", summary)
            .apply()
    }

    private fun loadSavedSession(): SavedSession? {
        val p = getSharedPreferences(SESSION_PREFS, Context.MODE_PRIVATE)
        if (!p.getBoolean("active", false)) return null
        val bin = p.getString("binPath", null) ?: return null
        val cfg = p.getString("configPath", null) ?: return null
        return SavedSession(
            binPath = bin,
            configPath = cfg,
            useRoot = p.getBoolean("useRoot", false),
            method = p.getString("method", "combined") ?: "combined",
            summary = p.getString("summary", "Local SNI proxy") ?: "Local SNI proxy"
        )
    }

    private fun clearSavedSession() {
        getSharedPreferences(SESSION_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean("active", false)
            .apply()
    }

    companion object {
        const val ACTION_STOP = "com.sakuranet.snispoof.STOP"
        const val ACTION_RESTART = "com.sakuranet.snispoof.RESTART"
        const val ACTION_ENSURE_ALIVE = "com.sakuranet.snispoof.ENSURE_ALIVE"
        const val EXTRA_CONFIG_PATH = "config_path"
        const val EXTRA_BIN_PATH = "bin_path"
        const val EXTRA_USE_ROOT = "use_root"
        const val EXTRA_METHOD = "spoof_method"
        const val EXTRA_ROUTE_SUMMARY = "route_summary"
        private const val CHANNEL_ID = "sni_spoof"
        private const val SESSION_PREFS = "sni_service_session"
        private const val NOTIF_ID = 1

        fun isSessionSavedActive(context: Context): Boolean {
            return context.getSharedPreferences(SESSION_PREFS, Context.MODE_PRIVATE)
                .getBoolean("active", false)
        }

        fun ensureRunningIfSavedActive(context: Context) {
            if (!isSessionSavedActive(context)) return
            val i = Intent(context, SniSpoofService::class.java).setAction(ACTION_ENSURE_ALIVE)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(i)
                } else {
                    context.startService(i)
                }
            } catch (_: Exception) {
            }
        }

        fun start(
            context: Context,
            bin: File,
            config: File,
            useRoot: Boolean,
            method: String,
            routeSummary: String = ""
        ) {
            val i = Intent(context, SniSpoofService::class.java)
                .putExtra(EXTRA_BIN_PATH, bin.absolutePath)
                .putExtra(EXTRA_CONFIG_PATH, config.absolutePath)
                .putExtra(EXTRA_USE_ROOT, useRoot)
                .putExtra(EXTRA_METHOD, method)
                .putExtra(EXTRA_ROUTE_SUMMARY, routeSummary)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        }

        fun stop(context: Context) {
            context.startService(Intent(context, SniSpoofService::class.java).setAction(ACTION_STOP))
        }
    }
}

/**
 * Thread-safe in-memory ring buffer and service status bus so the Activity's
 * status indicator and log console stay synchronized across recompositions.
 */
object LogBus {
    private val lines = ArrayDeque<String>()
    private val listeners = mutableListOf<(String) -> Unit>()
    private val stateListeners = mutableListOf<(Boolean) -> Unit>()
    private var runningState = false
    private var startedAtMs: Long = 0L
    private const val MAX = 500
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private val _linesFlow = MutableStateFlow<List<String>>(emptyList())
    val linesFlow: StateFlow<List<String>> = _linesFlow

    private val _runningFlow = MutableStateFlow(false)
    val runningFlow: StateFlow<Boolean> = _runningFlow

    private val _wakeLockFlow = MutableStateFlow(false)
    val wakeLockFlow: StateFlow<Boolean> = _wakeLockFlow

    private val _lastTrafficMsFlow = MutableStateFlow(0L)
    val lastTrafficMsFlow: StateFlow<Long> = _lastTrafficMsFlow

    private val _connectionCountFlow = MutableStateFlow(0)
    val connectionCountFlow: StateFlow<Int> = _connectionCountFlow

    @Synchronized
    fun recordSilentConnection() {
        _lastTrafficMsFlow.value = System.currentTimeMillis()
        _connectionCountFlow.value = _connectionCountFlow.value + 1
    }

    @Synchronized
    fun recordProcessTraffic(line: String) {
        val lower = line.lowercase(Locale.US)
        if (!lower.startsWith("[service]") && !lower.startsWith("[warn]") && !lower.startsWith("[error]")) {
            _lastTrafficMsFlow.value = System.currentTimeMillis()
            if (lower.contains(" -> ") || lower.contains("conn") || lower.contains("sni") ||
                lower.contains("hello") || lower.contains("relay") || lower.contains("inject") ||
                lower.contains("fragment") || lower.contains("accept")
            ) {
                _connectionCountFlow.value = _connectionCountFlow.value + 1
            }
        }
    }

    @Synchronized
    fun push(line: String) {
        val ts = timeFormat.format(Date())
        val formatted = if (line.startsWith("[") && line.length > 10 && line[3] == ':') {
            line
        } else {
            "[$ts] $line"
        }
        lines.addLast(formatted)
        if (lines.size > MAX) lines.removeFirst()
        val currentSnapshot = lines.toList()
        _linesFlow.value = currentSnapshot
        val snapshotListeners = listeners.toList()
        snapshotListeners.forEach { it(formatted) }
    }

    @Synchronized
    fun setRunning(isRunning: Boolean) {
        runningState = isRunning
        startedAtMs = if (isRunning) System.currentTimeMillis() else 0L
        if (!isRunning) {
            _lastTrafficMsFlow.value = 0L
        }
        _runningFlow.value = isRunning
        val snapshotStateListeners = stateListeners.toList()
        snapshotStateListeners.forEach { it(isRunning) }
    }

    @Synchronized
    fun setWakeLockHeld(held: Boolean) {
        _wakeLockFlow.value = held
    }

    @Synchronized
    fun isRunning(): Boolean = runningState

    @Synchronized
    fun startedAtMillis(): Long = startedAtMs

    @Synchronized
    fun clear() {
        lines.clear()
        _linesFlow.value = emptyList()
        val snapshotListeners = listeners.toList()
        snapshotListeners.forEach { it("") }
    }

    @Synchronized
    fun snapshot(): List<String> = lines.toList()

    @Synchronized
    fun subscribe(l: (String) -> Unit) {
        listeners.add(l)
    }

    @Synchronized
    fun unsubscribe(l: (String) -> Unit) {
        listeners.remove(l)
    }

    @Synchronized
    fun subscribeState(l: (Boolean) -> Unit) {
        stateListeners.add(l)
    }

    @Synchronized
    fun unsubscribeState(l: (Boolean) -> Unit) {
        stateListeners.remove(l)
    }
}
