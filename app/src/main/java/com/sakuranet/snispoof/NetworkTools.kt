package com.sakuranet.snispoof

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class TcpProbeResult(
    val host: String,
    val port: Int,
    val reachable: Boolean,
    val rttMs: Long,
    val detail: String
)

data class SniProbeResult(
    val sniDomain: String,
    val success: Boolean,
    val handshakeMs: Long,
    val protocol: String,
    val detail: String
)

data class BoundSocketResult(
    val socket: Socket,
    val boundIface: String?,
    val bindSucceeded: Boolean,
    val vpnActive: Boolean,
    val bindError: String? = null
)

object NetworkTools {

    @Volatile
    private var cachedPhysicalNet: Pair<Network, String>? = null

    @Volatile
    private var trackerRegistered: Boolean = false

    private val trackerLock = Any()
    private val dnsCache = ConcurrentHashMap<String, InetAddress>()
    private val vpnStateListeners = mutableListOf<(Boolean, String) -> Unit>()

    fun addVpnStateListener(listener: (Boolean, String) -> Unit) {
        synchronized(vpnStateListeners) {
            vpnStateListeners.add(listener)
        }
    }

    fun removeVpnStateListener(listener: (Boolean, String) -> Unit) {
        synchronized(vpnStateListeners) {
            vpnStateListeners.remove(listener)
        }
    }

    private fun notifyVpnState(vpnActive: Boolean, physIface: String) {
        val snapshot = synchronized(vpnStateListeners) { vpnStateListeners.toList() }
        snapshot.forEach { runCatching { it(vpnActive, physIface) } }
    }

    /**
     * Registers a persistent `NET_CAPABILITY_NOT_VPN` network callback & request so Android
     * keeps the underlying physical Wi-Fi / Cellular [Network] (`wlan0` / `rmnet_data0`)
     * alive and pinned in memory even when this app moves to the background and v2rayNG
     * activates its `tun0` VPN service.
     */
    fun ensurePhysicalNetworkTracker(context: Context) {
        val appCtx = context.applicationContext
        // Immediately refresh from current networks while we may be in foreground
        refreshCachedPhysicalNetwork(appCtx)

        if (trackerRegistered) return
        synchronized(trackerLock) {
            if (trackerRegistered) return
            val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return

            val physReq = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            val physCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    updateCandidatePhysicalNetwork(cm, network)
                }

                override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                    updateCandidatePhysicalNetwork(cm, network, networkCapabilities)
                }

                override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                    updateCandidatePhysicalNetwork(cm, network, null, linkProperties)
                }

                override fun onLost(network: Network) {
                    val current = cachedPhysicalNet
                    if (current?.first == network) {
                        cachedPhysicalNet = null
                        refreshCachedPhysicalNetwork(appCtx)
                    }
                }
            }

            try {
                cm.registerNetworkCallback(physReq, physCallback)
                trackerRegistered = true
            } catch (_: Exception) {
            }

            // Also request the physical network actively if CHANGE_NETWORK_STATE is granted
            try {
                cm.requestNetwork(physReq, object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        updateCandidatePhysicalNetwork(cm, network)
                    }
                })
            } catch (_: Exception) {
            }

            // Also watch for VPN (TRANSPORT_VPN) turning on/off so we can immediately re-verify bypass rules
            try {
                val vpnReq = NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
                cm.registerNetworkCallback(vpnReq, object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        val pair = refreshCachedPhysicalNetwork(appCtx) ?: cachedPhysicalNet
                        notifyVpnState(true, pair?.second.orEmpty())
                    }

                    override fun onLost(network: Network) {
                        val pair = refreshCachedPhysicalNetwork(appCtx) ?: cachedPhysicalNet
                        notifyVpnState(false, pair?.second.orEmpty())
                    }
                })
            } catch (_: Exception) {
            }
        }
    }

    private fun updateCandidatePhysicalNetwork(
        cm: ConnectivityManager,
        network: Network,
        capsHint: NetworkCapabilities? = null,
        linkHint: LinkProperties? = null
    ) {
        try {
            val caps = capsHint ?: cm.getNetworkCapabilities(network) ?: return
            val isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            if (isVpn) return

            val link = linkHint ?: cm.getLinkProperties(network)
            val iface = link?.interfaceName.orEmpty()
            if (iface.startsWith("tun", ignoreCase = true) ||
                iface.startsWith("ppp", ignoreCase = true)
            ) {
                return
            }

            val label = iface.ifBlank {
                when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wlan0"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "rmnet_data0"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "eth0"
                    else -> "phys0"
                }
            }

            val existing = cachedPhysicalNet
            if (existing == null || existing.first == network || caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                cachedPhysicalNet = Pair(network, label)
            }
        } catch (_: Exception) {
        }
    }

    private fun refreshCachedPhysicalNetwork(context: Context): Pair<Network, String>? {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return cachedPhysicalNet

            data class Candidate(
                val network: Network,
                val iface: String,
                val priority: Int
            )

            val candidates = mutableListOf<Candidate>()

            // Check activeNetwork first in case VPN is not yet active
            cm.activeNetwork?.let { active ->
                val caps = cm.getNetworkCapabilities(active)
                if (caps != null &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                ) {
                    val iface = cm.getLinkProperties(active)?.interfaceName.orEmpty()
                    if (!iface.startsWith("tun", ignoreCase = true)) {
                        val label = iface.ifBlank {
                            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) "wlan0" else "rmnet_data0"
                        }
                        candidates.add(Candidate(active, label, 200))
                    }
                }
            }

            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                val isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                if (isVpn) continue

                val linkProps = cm.getLinkProperties(net)
                val iface = linkProps?.interfaceName.orEmpty()
                if (iface.startsWith("tun", ignoreCase = true) ||
                    iface.startsWith("ppp", ignoreCase = true)
                ) {
                    continue
                }

                val internetBonus = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) 50 else 0
                val validatedBonus = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0
                val transportScore = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 40
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 35
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 30
                    else -> 10
                }
                if (internetBonus == 0 && transportScore <= 10) continue

                val label = iface.ifBlank {
                    when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wlan0"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "rmnet_data0"
                        else -> "phys0"
                    }
                }
                candidates.add(Candidate(net, label, validatedBonus + internetBonus + transportScore))
            }

            val best = candidates.maxByOrNull { it.priority }
            if (best != null) {
                val pair = Pair(best.network, best.iface)
                cachedPhysicalNet = pair
                pair
            } else {
                cachedPhysicalNet
            }
        } catch (_: Exception) {
            cachedPhysicalNet
        }
    }

    /**
     * Finds the active underlying physical [Network] (Wi-Fi, Ethernet, or Cellular) that is NOT
     * a VPN (`TRANSPORT_VPN`), using both the live `NET_CAPABILITY_NOT_VPN` tracker cache and
     * `ConnectivityManager` inspection so it never fails when the app is in the background.
     */
    fun findPhysicalUnderlyingNetwork(context: Context): Pair<Network, String>? {
        cachedPhysicalNet?.let { return it }
        return refreshCachedPhysicalNetwork(context)
    }

    fun isVpnCurrentlyActive(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
            val activeCaps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            if (activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return true
            cm.allNetworks.any { net ->
                cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Creates a new outbound [Socket] and binds it directly to the physical non-VPN [Network]
     * BEFORE setting socket options or calling `connect()`, preventing Android's `libnetd_client`
     * from attaching the default `tun0` VPN fwmark.
     */
    fun createAndBindPhysicalSocket(
        context: Context,
        bypassVpn: Boolean,
        tcpNoDelay: Boolean
    ): BoundSocketResult {
        val vpnActive = isVpnCurrentlyActive(context)
        if (!bypassVpn) {
            val plain = Socket()
            runCatching {
                plain.tcpNoDelay = tcpNoDelay
                plain.keepAlive = true
            }
            return BoundSocketResult(
                socket = plain,
                boundIface = null,
                bindSucceeded = true,
                vpnActive = vpnActive
            )
        }

        val physPair = findPhysicalUnderlyingNetwork(context) ?: refreshCachedPhysicalNetwork(context)
        if (physPair == null) {
            val fallback = Socket()
            runCatching {
                fallback.tcpNoDelay = tcpNoDelay
                fallback.keepAlive = true
            }
            return BoundSocketResult(
                socket = fallback,
                boundIface = null,
                bindSucceeded = false,
                vpnActive = vpnActive,
                bindError = "No physical non-VPN network found"
            )
        }

        val (physNet, iface) = physPair
        var lastError: String? = null

        // Method 1: Create via physNet.socketFactory (binds FD at creation time in AOSP NetworkBoundSocketFactory)
        try {
            val sfSocket = physNet.socketFactory.createSocket()
            runCatching { physNet.bindSocket(sfSocket) }
            RootShell.tryBindSocketToDevice(sfSocket, iface)
            runCatching {
                sfSocket.tcpNoDelay = tcpNoDelay
                sfSocket.keepAlive = true
            }
            return BoundSocketResult(
                socket = sfSocket,
                boundIface = iface,
                bindSucceeded = true,
                vpnActive = vpnActive
            )
        } catch (e: Exception) {
            lastError = e.message ?: e.javaClass.simpleName
        }

        // Method 2: Create unconnected Socket(), bindSocket immediately before setting options
        try {
            val rawSocket = Socket()
            physNet.bindSocket(rawSocket)
            RootShell.tryBindSocketToDevice(rawSocket, iface)
            runCatching {
                rawSocket.tcpNoDelay = tcpNoDelay
                rawSocket.keepAlive = true
            }
            return BoundSocketResult(
                socket = rawSocket,
                boundIface = iface,
                bindSucceeded = true,
                vpnActive = vpnActive
            )
        } catch (e: Exception) {
            lastError = e.message ?: e.javaClass.simpleName
        }

        // Method 3: Refresh physical network handle once in case netId rotated, then retry
        val refreshed = refreshCachedPhysicalNetwork(context)
        if (refreshed != null && refreshed.first != physNet) {
            try {
                val retrySocket = refreshed.first.socketFactory.createSocket()
                runCatching { refreshed.first.bindSocket(retrySocket) }
                RootShell.tryBindSocketToDevice(retrySocket, refreshed.second)
                runCatching {
                    retrySocket.tcpNoDelay = tcpNoDelay
                    retrySocket.keepAlive = true
                }
                return BoundSocketResult(
                    socket = retrySocket,
                    boundIface = refreshed.second,
                    bindSucceeded = true,
                    vpnActive = vpnActive
                )
            } catch (e: Exception) {
                lastError = e.message ?: e.javaClass.simpleName
            }
        }

        // Fallback: return socket with SO_BINDTODEVICE attempt, marking bindSucceeded = false
        val fallbackSocket = Socket()
        val devBound = RootShell.tryBindSocketToDevice(fallbackSocket, iface)
        runCatching {
            fallbackSocket.tcpNoDelay = tcpNoDelay
            fallbackSocket.keepAlive = true
        }
        return BoundSocketResult(
            socket = fallbackSocket,
            boundIface = if (devBound) iface else null,
            bindSucceeded = devBound,
            vpnActive = vpnActive,
            bindError = lastError
        )
    }

    /**
     * Binds an existing [socket] directly to the underlying physical non-VPN [Network].
     */
    fun bindSocketToPhysicalNetwork(context: Context, socket: Socket): String? {
        return try {
            val (physNet, iface) = findPhysicalUnderlyingNetwork(context)
                ?: refreshCachedPhysicalNetwork(context)
                ?: return null
            physNet.bindSocket(socket)
            RootShell.tryBindSocketToDevice(socket, iface)
            iface
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Resolves [host] to an [InetAddress] without ever touching the `tun0` VPN DNS server:
     * - For IPv4 literals (e.g. `172.66.129.89`), constructs the 4-byte [InetAddress] directly in 0ms.
     * - For domain names, queries the physical non-VPN [Network.getByName] and caches the result.
     */
    fun resolveTargetInetAddress(
        context: Context,
        host: String,
        bypassVpn: Boolean = true
    ): InetAddress {
        val clean = host.trim()
            .removePrefix("[")
            .removeSuffix("]")
        // Fast path for standard dotted-quad IPv4 literal: zero DNS calls, never touches tun0!
        parseIpv4Literal(clean)?.let { ipv4Bytes ->
            return InetAddress.getByAddress(clean, ipv4Bytes)
        }
        dnsCache[clean]?.let { return it }

        val resolved = if (bypassVpn) {
            val physNet = findPhysicalUnderlyingNetwork(context)?.first
            if (physNet != null) {
                runCatching { physNet.getByName(clean) }.getOrNull() ?: InetAddress.getByName(clean)
            } else {
                InetAddress.getByName(clean)
            }
        } else {
            InetAddress.getByName(clean)
        }
        dnsCache[clean] = resolved
        return resolved
    }

    private fun parseIpv4Literal(ip: String): ByteArray? {
        val parts = ip.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for (i in 0..3) {
            val n = parts[i].toIntOrNull() ?: return null
            if (n !in 0..255) return null
            bytes[i] = n.toByte()
        }
        return bytes
    }

    fun describePhysicalNetwork(context: Context): String {
        val pair = findPhysicalUnderlyingNetwork(context)
        return if (pair != null) {
            "${pair.second} (VPN-bypass bound)"
        } else {
            "system-default"
        }
    }

    /**
     * Resolves a hostname or domain to all IPv4/IPv6 addresses using the physical network DNS
     * when available, falling back to system DNS.
     */
    suspend fun resolveDomainIps(
        host: String,
        context: Context? = null
    ): Result<List<String>> = withContext(Dispatchers.IO) {
        runCatching {
            val cleaned = host.trim()
                .removePrefix("https://")
                .removePrefix("http://")
                .substringBefore("/")
                .substringBefore(":")
            require(cleaned.isNotBlank()) { "Please enter a valid domain or hostname" }
            val physNet = context?.let { findPhysicalUnderlyingNetwork(it)?.first }
            val addresses = if (physNet != null) {
                runCatching { physNet.getAllByName(cleaned) }.getOrNull()
                    ?: InetAddress.getAllByName(cleaned)
            } else {
                InetAddress.getAllByName(cleaned)
            }
            addresses.mapNotNull { it.hostAddress }.distinct()
        }
    }

    /**
     * Measures real TCP connection handshake latency (RTT) to [host]:[port].
     * Binds to the physical non-VPN network for non-loopback targets when [context] is provided.
     */
    suspend fun testTcpLatency(
        host: String,
        port: Int,
        timeoutMs: Int = 3500,
        context: Context? = null
    ): TcpProbeResult = withContext(Dispatchers.IO) {
        val cleanHost = host.trim()
        val startNs = System.nanoTime()
        try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                val isLoopback = cleanHost == "127.0.0.1" || cleanHost == "localhost" || cleanHost == "::1"
                val boundIface = if (!isLoopback && context != null) {
                    bindSocketToPhysicalNetwork(context, socket)
                } else {
                    null
                }
                socket.connect(InetSocketAddress(cleanHost, port), timeoutMs)
                val elapsedMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L)
                val viaSuffix = if (boundIface != null) " via $boundIface" else ""
                TcpProbeResult(
                    host = cleanHost,
                    port = port,
                    reachable = true,
                    rttMs = elapsedMs,
                    detail = "TCP connected in ${elapsedMs}ms$viaSuffix"
                )
            }
        } catch (e: Exception) {
            val elapsedMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L)
            TcpProbeResult(
                host = cleanHost,
                port = port,
                reachable = false,
                rttMs = elapsedMs,
                detail = e.message ?: e.javaClass.simpleName
            )
        }
    }

    /**
     * Performs a real TLS ClientHello/ServerHello handshake against [edgeIp]:[edgePort]
     * while setting the TLS SNI extension to [candidateSni], binding to the physical
     * network so active VPN tunnels (`tun0`) do not intercept the probe.
     */
    suspend fun probeSniDomain(
        edgeIp: String,
        edgePort: Int,
        candidateSni: String,
        timeoutMs: Int = 3500,
        context: Context? = null
    ): SniProbeResult = withContext(Dispatchers.IO) {
        val cleanIp = edgeIp.trim()
        val cleanSni = candidateSni.trim()
        val startNs = System.nanoTime()
        try {
            val sslContext = SSLContext.getInstance("TLS")
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            })
            sslContext.init(null, trustAll, SecureRandom())

            Socket().use { rawSocket ->
                rawSocket.tcpNoDelay = true
                rawSocket.soTimeout = timeoutMs
                if (context != null) {
                    bindSocketToPhysicalNetwork(context, rawSocket)
                }
                rawSocket.connect(InetSocketAddress(cleanIp, edgePort), timeoutMs)

                val sslSocket = sslContext.socketFactory.createSocket(
                    rawSocket,
                    cleanSni,
                    edgePort,
                    true
                ) as SSLSocket

                sslSocket.use { tls ->
                    tls.soTimeout = timeoutMs
                    val params = tls.sslParameters
                    params.serverNames = listOf(SNIHostName(cleanSni))
                    tls.sslParameters = params
                    tls.startHandshake()

                    val elapsedMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L)
                    val proto = tls.session?.protocol ?: "TLS"
                    val cipher = tls.session?.cipherSuite ?: ""
                    SniProbeResult(
                        sniDomain = cleanSni,
                        success = true,
                        handshakeMs = elapsedMs,
                        protocol = proto,
                        detail = "$proto • ${cipher.substringAfterLast("_WITH_")}"
                    )
                }
            }
        } catch (e: Exception) {
            val elapsedMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L)
            SniProbeResult(
                sniDomain = cleanSni,
                success = false,
                handshakeMs = elapsedMs,
                protocol = "FAIL",
                detail = e.message ?: e.javaClass.simpleName
            )
        }
    }

    /**
     * Scans a list of candidate SNI domains concurrently against [edgeIp]:[edgePort].
     */
    suspend fun scanCandidateSnis(
        edgeIp: String,
        edgePort: Int,
        domains: List<String>,
        timeoutMs: Int = 3500,
        context: Context? = null,
        onProgress: (SniProbeResult) -> Unit = {}
    ): List<SniProbeResult> = coroutineScope {
        val uniqueDomains = domains.map { it.trim() }.filter { it.isNotBlank() }.distinct()
        val results = uniqueDomains.map { domain ->
            async(Dispatchers.IO) {
                val res = probeSniDomain(edgeIp, edgePort, domain, timeoutMs, context)
                onProgress(res)
                res
            }
        }.awaitAll()

        results.sortedWith(
            compareByDescending<SniProbeResult> { it.success }
                .thenBy { it.handshakeMs }
        )
    }

    /**
     * Inspects `/proc/net/tcp` and `/proc/net/tcp6` to count listening (`0A`) and
     * established (`01`) sockets matching the local proxy [listenPort].
     */
    suspend fun inspectLocalProxySockets(listenPort: Int): Pair<Boolean, Int> = withContext(Dispatchers.IO) {
        val hexPort = "%04X".format(listenPort.coerceIn(1, 65535))
        var isListening = false
        var establishedCount = 0

        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { path ->
            runCatching {
                java.io.File(path).forEachLine { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && !trimmed.startsWith("sl")) {
                        val parts = trimmed.split(Regex("\\s+"))
                        if (parts.size >= 4) {
                            val localAddr = parts[1].uppercase()
                            val stateHex = parts[3].uppercase()
                            if (localAddr.endsWith(":$hexPort")) {
                                if (stateHex == "0A") {
                                    isListening = true
                                } else if (stateHex == "01") {
                                    establishedCount++
                                }
                            }
                        }
                    }
                }
            }
        }
        Pair(isListening, establishedCount)
    }

    fun formatThroughput(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1024 * 1024 -> "%.1f MB/s".format(bytesPerSec / (1024f * 1024f))
            bytesPerSec >= 1024 -> "%.1f KB/s".format(bytesPerSec / 1024f)
            else -> "$bytesPerSec B/s"
        }
    }

    /**
     * Queries the current device internet connectivity state via [ConnectivityManager],
     * including whether a VPN tunnel (`tun0`) is active and which physical network interface
     * (`wlan0`, `rmnet_data0`, etc.) is backing our VPN-bypass sockets.
     */
    fun queryCurrentNetworkStatus(context: Context): DeviceNetworkStatus {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return DeviceNetworkStatus(hasInternet = false, transportLabel = "Disconnected")

            val physPair = findPhysicalUnderlyingNetwork(context)
            val physIface = physPair?.second.orEmpty()

            val activeNet = cm.activeNetwork
            val caps = activeNet?.let { cm.getNetworkCapabilities(it) }

            if (caps == null && physPair == null) {
                return DeviceNetworkStatus(hasInternet = false, transportLabel = "Offline")
            }

            val hasInternetCap = (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true) ||
                (physPair != null)
            val isValidated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            val vpnActive = (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) ||
                cm.allNetworks.any { net ->
                    cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                }

            val physCaps = physPair?.first?.let { cm.getNetworkCapabilities(it) } ?: caps
            val primaryTransport = when {
                physCaps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
                physCaps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular"
                physCaps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
                vpnActive -> "VPN"
                else -> "Online"
            }

            val label = when {
                !hasInternetCap -> "Offline"
                vpnActive && physIface.isNotBlank() -> "$primaryTransport ($physIface) + VPN"
                vpnActive -> "$primaryTransport + VPN"
                physIface.isNotBlank() -> "$primaryTransport ($physIface)"
                else -> primaryTransport
            }

            DeviceNetworkStatus(
                hasInternet = hasInternetCap,
                isValidated = isValidated,
                transportLabel = label,
                vpnActive = vpnActive,
                physicalInterface = physIface.ifBlank { primaryTransport }
            )
        } catch (_: Exception) {
            DeviceNetworkStatus(hasInternet = true, transportLabel = "Online")
        }
    }

    /**
     * Observes real-time connectivity changes using [ConnectivityManager.NetworkCallback].
     */
    fun observeNetworkConnectivity(context: Context): Flow<DeviceNetworkStatus> = callbackFlow {
        val appContext = context.applicationContext
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

        trySend(queryCurrentNetworkStatus(appContext))

        if (cm == null) {
            close()
            return@callbackFlow
        }

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                trySend(queryCurrentNetworkStatus(appContext))
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                trySend(queryCurrentNetworkStatus(appContext))
            }

            override fun onLost(network: Network) {
                trySend(queryCurrentNetworkStatus(appContext))
            }

            override fun onUnavailable() {
                trySend(
                    DeviceNetworkStatus(
                        hasInternet = false,
                        isValidated = false,
                        transportLabel = "Offline"
                    )
                )
            }
        }

        var registered = false
        try {
            cm.registerDefaultNetworkCallback(callback)
            registered = true
        } catch (_: Exception) {
        }

        awaitClose {
            if (registered) {
                runCatching { cm.unregisterNetworkCallback(callback) }
            }
        }
    }
}

data class DeviceNetworkStatus(
    val hasInternet: Boolean = true,
    val isValidated: Boolean = true,
    val transportLabel: String = "Online",
    val vpnActive: Boolean = false,
    val physicalInterface: String = "wlan0"
)

enum class ProxyTrafficState {
    OFFLINE,
    IDLE_LISTENING,
    PROCESSING_TRAFFIC
}

data class ProxyTrafficTelemetry(
    val state: ProxyTrafficState = ProxyTrafficState.OFFLINE,
    val portBound: Boolean = false,
    val activeConnections: Int = 0,
    val totalRelayedConnections: Int = 0,
    val rxBytesPerSec: Long = 0L,
    val txBytesPerSec: Long = 0L
)
