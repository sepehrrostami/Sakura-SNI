package com.sakuranet.snispoof

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

/**
 * Built-in VPN-Safe Multi-Method SNI Spoofing, Byte-Range Fragmentation & Payload Obfuscation Engine.
 *
 * Key capabilities:
 * 1. Runs directly inside our app's UID (`com.sakuranet.snispoof`) and explicitly binds every
 *    outbound socket to the underlying physical Wi-Fi / Cellular [android.net.Network] via
 *    [NetworkTools.bindSocketToPhysicalNetwork] so v2rayNG VPN mode (`tun0`) never loops traffic.
 * 2. Supports 6 DPI evasion methods (`combined`, `fragment`, `tls_record`, `oob`, `disorder`,
 *    `inject`). The real ClientHello bytes are only ever split, never edited, because any edit
 *    breaks the TLS transcript hash and the server aborts the handshake.
 * 3. Supports 8 fragmentation strategies including **Specific Byte-Range Splitting (`byte_range`)**
 *    and **SNI Extension Boundary Splitting (`sni_ext_boundary`)** with dynamic per-segment
 *    delay ranges (`delayRangeSpec`) and SNI offset shift (`sniOffsetShift`).
 * 4. Record-layer version cap (`tls10_0301`, `tls12_0303`) on the real ClientHello (safe: ignored
 *    by servers and not part of the transcript).
 * 5. **Decoy-only payload obfuscation** (SNI case, RFC 8701 GREASE, RFC 7685 padding) and
 *    low-TTL decoy payload modes (`fake_client_hello`, `zero_padded_hello`, `random_noise`,
 *    `http_get_decoy`) with repeat count (`decoyRepeats`).
 */
class SakuraProxyEngine(
    private val context: Context,
    private val config: SpoofConfig,
    private val useRoot: Boolean,
    private val onLine: (String) -> Unit,
    private val onExit: (Int) -> Unit
) {
    private val running = AtomicBoolean(false)
    private val activeConnections = AtomicInteger(0)
    @Volatile
    private var serverSocket: ServerSocket? = null
    private val executor = Executors.newCachedThreadPool()
    @Volatile
    private var lastAcceptLogMs: Long = 0L
    @Volatile
    private var lastLoopWarnMs: Long = 0L

    fun isRunning(): Boolean = running.get()

    fun isListenerHealthy(): Boolean {
        val srv = serverSocket
        return running.get() && srv != null && srv.isBound && !srv.isClosed
    }

    fun start(): Boolean {
        if (!running.compareAndSet(false, true)) return true
        return try {
            NetworkTools.ensurePhysicalNetworkTracker(context)
            val srv = bindNewServerSocket()
            serverSocket = srv

            val physInfo = NetworkTools.describePhysicalNetwork(context)
            val pipelineDesc = TlsClientHelloManipulator.describePipelineSummary(config)
            val listenPort = config.listenPort.coerceIn(1, 65535)
            onLine(
                "listening on 127.0.0.1:$listenPort -> ${config.connectIp}:${config.connectPort} " +
                    "(method=${config.method} strategy=${config.fragmentStrategy} fake_sni=${config.fakeSni} net=$physInfo)"
            )
            onLine("[pipeline] $pipelineDesc")

            executor.execute { acceptLoop(srv) }
            true
        } catch (e: Exception) {
            running.set(false)
            onLine("[error] Failed to bind local listener 127.0.0.1:${config.listenPort}: ${e.message}")
            onExit(-1)
            false
        }
    }

    private fun bindNewServerSocket(): ServerSocket {
        val listenPort = config.listenPort.coerceIn(1, 65535)
        val loopback = InetAddress.getByAddress("127.0.0.1", byteArrayOf(127, 0, 0, 1))
        val srv = ServerSocket()
        srv.reuseAddress = true
        srv.bind(InetSocketAddress(loopback, listenPort), 256)
        return srv
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null
        runCatching { executor.shutdownNow() }
        onExit(0)
    }

    private fun acceptLoop(initialSrv: ServerSocket) {
        var currentSrv = initialSrv
        try {
            while (running.get()) {
                if (currentSrv.isClosed || !currentSrv.isBound) {
                    if (!running.get()) break
                    try {
                        Thread.sleep(150)
                        currentSrv = bindNewServerSocket()
                        serverSocket = currentSrv
                        onLine("[service] Re-bound local listener 127.0.0.1:${config.listenPort} after network transition")
                    } catch (rebindErr: Exception) {
                        Thread.sleep(500)
                        continue
                    }
                }

                val client = try {
                    currentSrv.accept()
                } catch (e: Exception) {
                    if (!running.get()) break
                    // Transient accept exception (e.g., ECONNABORTED when v2rayNG switches to VPN mode)
                    // Do NOT exit the accept loop or stop the service!
                    try {
                        Thread.sleep(30)
                    } catch (_: InterruptedException) {
                        break
                    }
                    continue
                }

                if (activeConnections.get() >= 180) {
                    // Guard against socket/thread exhaustion during connection storms
                    runCatching { client.close() }
                    continue
                }

                try {
                    executor.execute { handleClient(client) }
                } catch (_: Exception) {
                    runCatching { client.close() }
                }
            }
        } finally {
            if (running.get()) {
                running.set(false)
                onExit(0)
            }
        }
    }

    private fun handleClient(clientSocket: Socket) {
        val cleanTargetHost = config.connectIp.trim()
        val targetPort = config.connectPort.coerceIn(1, 65535)

        // Prevent self-loop if target points back to our own local listener
        if ((cleanTargetHost == "127.0.0.1" || cleanTargetHost.equals("localhost", ignoreCase = true)) &&
            targetPort == config.listenPort
        ) {
            runCatching { clientSocket.close() }
            return
        }

        activeConnections.incrementAndGet()
        var upstreamSocket: Socket? = null
        try {
            clientSocket.tcpNoDelay = true
            clientSocket.soTimeout = config.handshakeTimeoutMs.coerceIn(1000, 30000)

            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()

            // Read initial client payload (typically TLS ClientHello from v2rayNG)
            val firstPacket = readInitialPayload(clientIn) ?: return

            // Open upstream socket bound directly to physical Wi-Fi / Cellular network BEFORE setting options
            val boundRes = NetworkTools.createAndBindPhysicalSocket(
                context = context,
                bypassVpn = config.bypassVpnTun,
                tcpNoDelay = config.tcpNoDelay
            )
            val upstream = boundRes.socket
            upstreamSocket = upstream
            val boundIface = boundRes.boundIface

            // Circuit breaker: If VPN (tun0) is active and physical network binding failed on a non-rooted
            // device, do NOT connect into tun0 (which would cause an infinite loop with v2rayNG!).
            if (config.bypassVpnTun && boundRes.vpnActive && !boundRes.bindSucceeded && !useRoot) {
                val now = System.currentTimeMillis()
                if (now - lastLoopWarnMs > 4000L) {
                    lastLoopWarnMs = now
                    onLine(
                        "[error] VPN loop prevented: Android VPN blocked physical socket bind (${boundRes.bindError ?: "EPERM"}). " +
                            "In v2rayNG Settings -> Per-App Proxy, enable Bypass for SakuraNet (com.sakuranet.snispoof)!"
                    )
                }
                return
            }

            val targetInetAddr = try {
                NetworkTools.resolveTargetInetAddress(context, cleanTargetHost, config.bypassVpnTun)
            } catch (dnsErr: Exception) {
                val now = System.currentTimeMillis()
                if (now - lastAcceptLogMs > 2000L) {
                    lastAcceptLogMs = now
                    onLine("[warn] DNS resolve failed for $cleanTargetHost: ${dnsErr.message}")
                }
                return
            }

            try {
                upstream.connect(
                    InetSocketAddress(targetInetAddr, targetPort),
                    config.connectTimeoutMs.coerceIn(1000, 30000)
                )
            } catch (connectErr: Exception) {
                val now = System.currentTimeMillis()
                if (now - lastAcceptLogMs > 1200L) {
                    lastAcceptLogMs = now
                    onLine(
                        "[warn] dial upstream $cleanTargetHost:$targetPort " +
                            "(iface=${boundIface ?: "default"}): ${connectErr.message}"
                    )
                }
                return
            }

            // Reset read timeout for long-lived tunnel relay after handshake
            clientSocket.soTimeout = 0
            upstream.soTimeout = 0

            val upstreamIn = upstream.getInputStream()
            val upstreamOut = upstream.getOutputStream()

            // Deliver initial TLS ClientHello handshake FIRST for minimum latency
            deliverInitialHandshake(
                upstreamSocket = upstream,
                upstreamOut = upstreamOut,
                firstPacket = firstPacket
            )

            // Rate-limit connection log emission so bursts from v2rayNG VPN never stall threads
            if (config.logLevel == "debug" || config.logLevel == "info") {
                val now = System.currentTimeMillis()
                if (now - lastAcceptLogMs >= 250L) {
                    lastAcceptLogMs = now
                    val detectedSni = TlsClientHelloManipulator.extractSniHostname(firstPacket)
                    onLine(
                        "accept conn -> $cleanTargetHost:$targetPort " +
                            "[method=${config.method} strategy=${config.fragmentStrategy} " +
                            "orig_sni=${detectedSni ?: "tls/raw"} fake_sni=${config.fakeSni} iface=${boundIface ?: "sys"}]"
                    )
                } else {
                    LogBus.recordSilentConnection()
                }
            } else {
                LogBus.recordSilentConnection()
            }

            // Bidirectional full-duplex relay
            val reverseFuture = executor.submit {
                pumpStream(upstreamIn, clientOut)
                runCatching { clientSocket.shutdownOutput() }
            }
            pumpStream(clientIn, upstreamOut)
            runCatching { upstream.shutdownOutput() }
            runCatching { reverseFuture.get() }
        } catch (e: Exception) {
            if (running.get() && config.logLevel == "debug") {
                onLine("[debug] conn closed: ${e.message}")
            }
        } finally {
            runCatching { upstreamSocket?.close() }
            runCatching { clientSocket.close() }
            activeConnections.decrementAndGet()
        }
    }

    /**
     * Reads the client's first flight. When it starts with a TLS handshake record header, keeps
     * reading (bounded by the handshake read timeout) until the whole record has arrived, so the
     * SNI can still be located when the client wrote its ClientHello in several pieces.
     */
    private fun readInitialPayload(clientIn: InputStream): ByteArray? {
        val buf = ByteArray(5 + 16384)
        var total = try {
            clientIn.read(buf)
        } catch (_: Exception) {
            -1
        }
        if (total <= 0) return null
        if (total >= 5 && buf[0] == 0x16.toByte() && buf[1] == 0x03.toByte()) {
            val declaredLen = ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
            val recordEnd = (5 + declaredLen).coerceAtMost(buf.size)
            while (total < recordEnd) {
                val n = try {
                    clientIn.read(buf, total, recordEnd - total)
                } catch (_: Exception) {
                    -1
                }
                if (n <= 0) break
                total += n
            }
        }
        return buf.copyOfRange(0, total)
    }

    private fun deliverInitialHandshake(
        upstreamSocket: Socket,
        upstreamOut: OutputStream,
        firstPacket: ByteArray
    ) {
        ClientHelloSender.send(
            upstreamSocket = upstreamSocket,
            upstreamOut = upstreamOut,
            firstPacket = firstPacket,
            config = config,
            sendDecoyClientHello = { template -> sendDecoyClientHello(template) }
        )
    }

    /**
     * Schedules [SpoofConfig.decoyRepeats] best-effort decoy ClientHellos (carrying the Fake SNI)
     * on separate short-lived connections. They run on the executor, so the real connection is
     * never delayed by them.
     *
     * Note: an app without raw sockets cannot inject into the real TCP flow, so a DPI that tracks
     * each flow separately is not fooled by these; the fragmentation step does the real work.
     */
    private fun sendDecoyClientHello(templatePacket: ByteArray) {
        // Skip extra decoy TCP connections during high-concurrency bursts to preserve sockets
        if (activeConnections.get() > 24) return
        val repeats = config.decoyRepeats.coerceIn(1, 3)
        val decoyPayload = TlsClientHelloManipulator.buildDecoyPayload(templatePacket, config)
        val cleanHost = config.connectIp.trim()
        val port = config.connectPort.coerceIn(1, 65535)
        repeat(repeats) {
            try {
                executor.execute { sendSingleDecoy(cleanHost, port, decoyPayload) }
            } catch (_: Exception) {
                return // executor already shut down
            }
        }
    }

    /**
     * One decoy connection. The TCP handshake runs with the normal TTL (a low-TTL SYN never reaches
     * the server, so nothing would be sent at all); only after connecting is the TTL lowered, so the
     * decoy segment passes on-path DPI but expires before reaching the edge.
     */
    private fun sendSingleDecoy(host: String, port: Int, payload: ByteArray) {
        if (!running.get()) return
        var decoySocket: Socket? = null
        try {
            val targetAddr = NetworkTools.resolveTargetInetAddress(context, host, config.bypassVpnTun)
            val boundRes = NetworkTools.createAndBindPhysicalSocket(
                context = context,
                bypassVpn = config.bypassVpnTun,
                tcpNoDelay = true
            )
            val s = boundRes.socket
            decoySocket = s
            if (config.bypassVpnTun && boundRes.vpnActive && !boundRes.bindSucceeded && !useRoot) return
            s.soTimeout = 300
            s.connect(
                InetSocketAddress(targetAddr, port),
                config.connectTimeoutMs.coerceIn(500, 3000)
            )
            // Without a low TTL the decoy would simply reach the real server, so skip it.
            if (!RootShell.trySetSocketLowTtl(s, config.decoyTtl.coerceIn(1, 32))) return
            val out = s.getOutputStream()
            out.write(payload)
            out.flush()
            // Let the segment hit the wire, then drop the connection with an RST (SO_LINGER 0)
            // so the kernel does not keep retransmitting the expired decoy.
            Thread.sleep(30)
            runCatching { s.setSoLinger(true, 0) }
        } catch (_: Exception) {
            // Decoy connection is best-effort and intentionally short-lived
        } finally {
            runCatching { decoySocket?.close() }
        }
    }

    private fun pumpStream(input: InputStream, output: OutputStream) {
        val buf = ByteArray(32 * 1024)
        while (running.get()) {
            val n = try {
                input.read(buf)
            } catch (_: Exception) {
                -1
            }
            if (n <= 0) break
            output.write(buf, 0, n)
            output.flush()
        }
    }
}

/**
 * Writes the client's first flight (normally the TLS ClientHello) upstream using the configured
 * DPI-evasion method. Shared by [SakuraProxyEngine] and the method benchmark, so the benchmark
 * measures exactly what the proxy sends.
 */
object ClientHelloSender {
    fun send(
        upstreamSocket: Socket,
        upstreamOut: OutputStream,
        firstPacket: ByteArray,
        config: SpoofConfig,
        sendDecoyClientHello: (ByteArray) -> Unit
    ) {
        fun writeSegments(
            out: OutputStream,
            segments: List<ByteArray>,
            addJitter: Boolean = false
        ) {
            segments.forEachIndexed { idx, seg ->
                if (seg.isNotEmpty()) {
                    out.write(seg)
                    out.flush()
                    if (idx < segments.lastIndex) {
                        val baseWait = TlsClientHelloManipulator.computeNextDelayMs(
                            delayRangeSpec = config.delayRangeSpec,
                            fallbackDelayMs = config.fragmentDelayMs
                        )
                        if (baseWait > 0L) {
                            val wait = if (addJitter) {
                                baseWait + Random.nextLong(0L, (baseWait / 2L).coerceAtLeast(2L))
                            } else {
                                baseWait
                            }
                            Thread.sleep(wait)
                        }
                    }
                }
            }
        }

        val isTlsClientHello = TlsClientHelloManipulator.isTlsClientHello(firstPacket)
        if (!isTlsClientHello) {
            upstreamOut.write(firstPacket)
            upstreamOut.flush()
            return
        }

        // Only the record-layer version may be changed on the real ClientHello. Every byte of the
        // handshake message itself is covered by the TLS transcript hash, so editing it (SNI case,
        // GREASE, padding, SNI rewrite) makes the server's Finished check fail and the connection
        // dies. Those edits are applied to the decoy payload only (see buildDecoyPayload).
        val obfuscatedPacket = TlsClientHelloManipulator.applyRecordLayerObfuscation(firstPacket, config)

        when (config.method) {
            "tls_record" -> {
                val multiRecord = TlsClientHelloManipulator.splitIntoMultipleTlsRecords(
                    packet = obfuscatedPacket,
                    strategy = config.fragmentStrategy,
                    chunkSize = config.chunkSize,
                    byteRangeSpec = config.byteRangeSpec,
                    sniOffsetShift = config.sniOffsetShift
                )
                val chunks = TlsClientHelloManipulator.splitPacketWithConfig(multiRecord, config)
                writeSegments(upstreamOut, chunks)
            }

            "oob" -> {
                val splitOffset = TlsClientHelloManipulator.findSniShiftOffset(
                    packet = obfuscatedPacket,
                    sniOffsetShift = config.sniOffsetShift
                )
                val part1 = obfuscatedPacket.copyOfRange(0, splitOffset)
                val part2 = obfuscatedPacket.copyOfRange(splitOffset, obfuscatedPacket.size)
                upstreamOut.write(part1)
                upstreamOut.flush()
                runCatching {
                    upstreamSocket.oobInline = false
                    upstreamSocket.sendUrgentData(0x47) // Decoy urgent byte discarded by TLS server
                }
                val pauseMs = TlsClientHelloManipulator.computeNextDelayMs(
                    delayRangeSpec = config.delayRangeSpec,
                    fallbackDelayMs = config.fragmentDelayMs
                )
                if (pauseMs > 0) Thread.sleep(pauseMs)
                val subChunks = TlsClientHelloManipulator.splitPacket(
                    packet = part2,
                    strategy = if (config.fragmentStrategy == "byte_range") "byte_range" else "chunk",
                    chunkSize = config.chunkSize.coerceAtLeast(8),
                    fragmentCount = 2,
                    byteRangeSpec = config.byteRangeSpec,
                    sniOffsetShift = config.sniOffsetShift
                )
                writeSegments(upstreamOut, subChunks)
            }

            "inject" -> {
                sendDecoyClientHello(firstPacket)
                val pauseMs = TlsClientHelloManipulator.computeNextDelayMs(
                    delayRangeSpec = config.delayRangeSpec,
                    fallbackDelayMs = config.fragmentDelayMs
                )
                if (pauseMs > 0) Thread.sleep(pauseMs)
                upstreamOut.write(obfuscatedPacket)
                upstreamOut.flush()
            }

            "disorder" -> {
                sendDecoyClientHello(firstPacket)
                val multiRecord = TlsClientHelloManipulator.splitIntoMultipleTlsRecords(
                    packet = obfuscatedPacket,
                    strategy = config.fragmentStrategy,
                    chunkSize = config.chunkSize,
                    byteRangeSpec = config.byteRangeSpec,
                    sniOffsetShift = config.sniOffsetShift
                )
                val chunks = TlsClientHelloManipulator.splitPacketWithConfig(multiRecord, config)
                writeSegments(upstreamOut, chunks, addJitter = true)
            }

            "combined" -> {
                sendDecoyClientHello(firstPacket)
                val chunks = TlsClientHelloManipulator.splitPacketWithConfig(obfuscatedPacket, config)
                writeSegments(upstreamOut, chunks)
            }

            else -> {
                // "fragment" mode: pure TCP segment splitting (with payload obfuscation + byte-range slicing)
                val chunks = TlsClientHelloManipulator.splitPacketWithConfig(obfuscatedPacket, config)
                writeSegments(upstreamOut, chunks)
            }
        }
    }
}

/**
 * Pure Kotlin parser, byte-range slicer & payload obfuscator for TLS 1.2 / TLS 1.3 ClientHello records.
 */
object TlsClientHelloManipulator {

    private val GREASE_VALUES = intArrayOf(
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A
    )

    data class SniLocation(
        val extStartOffset: Int,
        val hostStartOffset: Int,
        val hostLength: Int,
        val hostname: String
    )

    fun isTlsClientHello(packet: ByteArray): Boolean {
        return packet.size >= 43 &&
            packet[0] == 0x16.toByte() && // TLS Handshake record
            packet[1] == 0x03.toByte() && // TLS Major version 3
            packet[5] == 0x01.toByte()    // Handshake type 1 = ClientHello
    }

    fun extractSniHostname(packet: ByteArray): String? =
        locateSni(packet)?.hostname

    fun findSniMidpointOffset(packet: ByteArray): Int {
        val loc = locateSni(packet)
        return if (loc != null && loc.hostLength >= 2) {
            (loc.hostStartOffset + (loc.hostLength / 2)).coerceIn(1, packet.size - 1)
        } else {
            (packet.size / 2).coerceAtLeast(1)
        }
    }

    fun findSniShiftOffset(packet: ByteArray, sniOffsetShift: Int): Int {
        val loc = locateSni(packet)
        return if (loc != null && loc.hostLength >= 2) {
            val shift = sniOffsetShift.coerceIn(1, (loc.hostLength - 1).coerceAtLeast(1))
            (loc.hostStartOffset + shift).coerceIn(1, packet.size - 1)
        } else {
            findSniMidpointOffset(packet)
        }
    }

    /**
     * Parses the TLS ClientHello record to find the exact byte offset and length of the SNI hostname.
     */
    fun locateSni(packet: ByteArray): SniLocation? {
        if (!isTlsClientHello(packet)) return null
        try {
            var pos = 5 // Skip 5-byte TLS Record Header
            pos += 4    // Skip 4-byte Handshake Header (type 1 + 3-byte length)
            pos += 2    // Skip 2-byte Client Version
            pos += 32   // Skip 32-byte Client Random
            if (pos >= packet.size) return null

            // Session ID
            val sessionIdLen = packet[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            if (pos + 2 > packet.size) return null

            // Cipher Suites
            val cipherSuitesLen = readUInt16(packet, pos)
            pos += 2 + cipherSuitesLen
            if (pos + 1 > packet.size) return null

            // Compression Methods
            val compMethodsLen = packet[pos].toInt() and 0xFF
            pos += 1 + compMethodsLen
            if (pos + 2 > packet.size) return null

            // Extensions total length
            val extensionsLen = readUInt16(packet, pos)
            pos += 2
            val extensionsEnd = (pos + extensionsLen).coerceAtMost(packet.size)

            while (pos + 4 <= extensionsEnd) {
                val extType = readUInt16(packet, pos)
                val extLen = readUInt16(packet, pos + 2)
                val extDataStart = pos + 4
                if (extDataStart + extLen > extensionsEnd) break

                if (extType == 0x0000 && extLen >= 5) {
                    // server_name extension: 2B list len + 1B name_type (0) + 2B host_len + host bytes
                    val nameType = packet[extDataStart + 2].toInt() and 0xFF
                    val hostLen = readUInt16(packet, extDataStart + 3)
                    val hostStart = extDataStart + 5
                    if (nameType == 0 && hostLen > 0 && hostStart + hostLen <= extDataStart + extLen) {
                        val hostStr = String(packet, hostStart, hostLen, StandardCharsets.US_ASCII)
                        return SniLocation(
                            extStartOffset = pos,
                            hostStartOffset = hostStart,
                            hostLength = hostLen,
                            hostname = hostStr
                        )
                    }
                }
                pos = extDataStart + extLen
            }
        } catch (_: Exception) {
        }
        return null
    }

    /**
     * The only change that is safe on the REAL ClientHello: the record-layer `legacy_record_version`
     * (`tls10_0301` / `tls12_0303`), which RFC 8446 says receivers must ignore and which is not part
     * of the handshake transcript. Returns a copy; [packet] is never mutated.
     */
    fun applyRecordLayerObfuscation(packet: ByteArray, config: SpoofConfig): ByteArray {
        if (!isTlsClientHello(packet)) return packet
        val minor = when (config.tlsRecordVersionCap) {
            "tls10_0301" -> 0x01
            "tls12_0303" -> 0x03
            else -> return packet
        }
        val out = packet.copyOf()
        out[1] = 0x03.toByte()
        out[2] = minor.toByte()
        return out
    }

    /**
     * Payload obfuscation for DECOY packets only (they are meant to be thrown away, so breaking
     * the TLS transcript does not matter there):
     * 1. In-place SNI Hostname Case Obfuscation (`alternating`, `random_mixed`, `upper_tld`)
     * 2. RFC 8701 GREASE Extension Injection (`greaseObfuscation`)
     * 3. RFC 7685 TLS Padding Extension (`0x0015`, `tlsPaddingSize` bytes)
     * 4. TLS Record Version Header Cap (`tls10_0301` or `tls12_0303`)
     *
     * Never call this on the real ClientHello: the server would reject the handshake.
     */
    fun applyDecoyObfuscation(packet: ByteArray, config: SpoofConfig): ByteArray {
        if (!isTlsClientHello(packet)) return packet
        var current = packet.copyOf()

        // 1. SNI Case Obfuscation
        if (config.sniCaseObfuscation != "none") {
            current = applySniCaseModeInPlace(current, config.sniCaseObfuscation)
        }

        // 2. RFC 8701 GREASE Extension Injection
        if (config.greaseObfuscation) {
            val greaseType = GREASE_VALUES[Random.nextInt(GREASE_VALUES.size)]
            val greaseData = Random.nextBytes(4)
            current = appendTlsExtension(current, greaseType, greaseData)
        }

        // 3. RFC 7685 Padding Extension (0x0015)
        val padBytesCount = config.tlsPaddingSize.coerceIn(0, 2048)
        if (padBytesCount > 0 && current.size + 4 + padBytesCount <= 16380) {
            val padPayload = ByteArray(padBytesCount) // RFC 7685 specifies zero-filled padding
            current = appendTlsExtension(current, 0x0015, padPayload)
        }

        // 4. TLS Record Version Header Cap
        when (config.tlsRecordVersionCap) {
            "tls10_0301" -> {
                current[1] = 0x03.toByte()
                current[2] = 0x01.toByte()
            }
            "tls12_0303" -> {
                current[1] = 0x03.toByte()
                current[2] = 0x03.toByte()
            }
        }

        return current
    }

    /**
     * Mutates the ASCII SNI hostname bytes inside [packet] according to [mode] without changing
     * packet length or offsets. DNS/TLS hostnames are case-insensitive per RFC 4343, while
     * case-sensitive DPI regex matchers fail to match mixed-case SNIs.
     */
    fun applySniCaseModeInPlace(packet: ByteArray, mode: String): ByteArray {
        if (mode == "none") return packet
        val loc = locateSni(packet) ?: return packet
        val start = loc.hostStartOffset
        val end = (start + loc.hostLength).coerceAtMost(packet.size)
        if (start >= end) return packet

        when (mode) {
            "alternating" -> {
                var toggle = false
                for (i in start until end) {
                    val b = packet[i].toInt() and 0xFF
                    if (b in 'a'.code..'z'.code || b in 'A'.code..'Z'.code) {
                        packet[i] = if (toggle) {
                            b.toChar().uppercaseChar().code.toByte()
                        } else {
                            b.toChar().lowercaseChar().code.toByte()
                        }
                        toggle = !toggle
                    }
                }
            }
            "random_mixed" -> {
                var changed = false
                for (i in start until end) {
                    val b = packet[i].toInt() and 0xFF
                    if (b in 'a'.code..'z'.code || b in 'A'.code..'Z'.code) {
                        val upper = Random.nextBoolean()
                        if (upper) changed = true
                        packet[i] = if (upper) {
                            b.toChar().uppercaseChar().code.toByte()
                        } else {
                            b.toChar().lowercaseChar().code.toByte()
                        }
                    }
                }
                if (!changed && end > start) {
                    val b = packet[start].toInt() and 0xFF
                    if (b in 'a'.code..'z'.code) {
                        packet[start] = b.toChar().uppercaseChar().code.toByte()
                    }
                }
            }
            "upper_tld" -> {
                var lastDot = -1
                for (i in (end - 1) downTo start) {
                    if (packet[i] == '.'.code.toByte()) {
                        lastDot = i
                        break
                    }
                }
                val targetStart = if (lastDot in start until (end - 1)) lastDot + 1 else start
                for (i in targetStart until end) {
                    val b = packet[i].toInt() and 0xFF
                    if (b in 'a'.code..'z'.code) {
                        packet[i] = b.toChar().uppercaseChar().code.toByte()
                    }
                }
            }
        }
        return packet
    }

    /**
     * Appends a TLS ClientHello extension (`[extType:2][extLen:2][extData]`) to the end of
     * the ClientHello extensions block and updates TLS Record, Handshake, and Extensions lengths.
     */
    fun appendTlsExtension(packet: ByteArray, extType: Int, extData: ByteArray): ByteArray {
        if (!isTlsClientHello(packet)) return packet
        return try {
            val recordPayloadLen = readUInt16(packet, 3)
            if (5 + recordPayloadLen != packet.size) return packet

            val handshakeLen = ((packet[6].toInt() and 0xFF) shl 16) or
                ((packet[7].toInt() and 0xFF) shl 8) or
                (packet[8].toInt() and 0xFF)

            var pos = 5 + 4 + 2 + 32
            if (pos >= packet.size) return packet
            val sessionIdLen = packet[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen
            if (pos + 2 > packet.size) return packet
            val cipherLen = readUInt16(packet, pos)
            pos += 2 + cipherLen
            if (pos + 1 > packet.size) return packet
            val compLen = packet[pos].toInt() and 0xFF
            pos += 1 + compLen
            if (pos + 2 > packet.size) return packet

            val extTotalLenOffset = pos
            val oldExtTotalLen = readUInt16(packet, extTotalLenOffset)
            val extEndOffset = extTotalLenOffset + 2 + oldExtTotalLen
            if (extEndOffset > packet.size) return packet

            val addedBytes = 4 + extData.size
            val result = ByteArray(packet.size + addedBytes)
            // Copy up to end of existing extensions
            System.arraycopy(packet, 0, result, 0, extEndOffset)
            // Write new extension header + payload
            writeUInt16(result, extEndOffset, extType and 0xFFFF)
            writeUInt16(result, extEndOffset + 2, extData.size)
            if (extData.isNotEmpty()) {
                System.arraycopy(extData, 0, result, extEndOffset + 4, extData.size)
            }
            // Copy any trailing bytes if present
            val trailing = packet.size - extEndOffset
            if (trailing > 0) {
                System.arraycopy(packet, extEndOffset, result, extEndOffset + addedBytes, trailing)
            }

            // Update TLS Record length, Handshake length, and Extensions total length
            writeUInt16(result, 3, recordPayloadLen + addedBytes)
            val newHsLen = handshakeLen + addedBytes
            result[6] = ((newHsLen ushr 16) and 0xFF).toByte()
            result[7] = ((newHsLen ushr 8) and 0xFF).toByte()
            result[8] = (newHsLen and 0xFF).toByte()
            writeUInt16(result, extTotalLenOffset, oldExtTotalLen + addedBytes)

            result
        } catch (_: Exception) {
            packet
        }
    }

    /**
     * Builds the decoy packet payload according to [SpoofConfig.decoyPayloadMode].
     */
    fun buildDecoyPayload(templatePacket: ByteArray, config: SpoofConfig): ByteArray {
        val cleanSni = config.fakeSni.trim().ifBlank { "speed.cloudflare.com" }

        // A decoy must never carry the real SNI. rewriteClientHelloSni returns its input unchanged
        // when it cannot parse the hello (partial read, multi-record), so verify the result and
        // fall back to a synthetic ClientHello.
        fun fakeHello(): ByteArray {
            val rewritten = rewriteClientHelloSni(templatePacket, cleanSni)
            return if (locateSni(rewritten)?.hostname == cleanSni) {
                rewritten
            } else {
                buildSyntheticClientHello(cleanSni)
            }
        }

        return when (config.decoyPayloadMode) {
            "zero_padded_hello" -> {
                applyDecoyObfuscation(appendTlsExtension(fakeHello(), 0x0015, ByteArray(128)), config)
            }
            "random_noise" -> {
                val noise = ByteArray(69)
                noise[0] = 0x16.toByte()
                noise[1] = 0x03.toByte()
                noise[2] = 0x01.toByte()
                noise[3] = 0x00.toByte()
                noise[4] = 0x40.toByte()
                val rnd = Random.nextBytes(64)
                System.arraycopy(rnd, 0, noise, 5, 64)
                noise
            }
            "http_get_decoy" -> {
                val http = "GET / HTTP/1.1\r\nHost: $cleanSni\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                http.toByteArray(StandardCharsets.US_ASCII)
            }
            else -> {
                applyDecoyObfuscation(fakeHello(), config)
            }
        }
    }

    fun splitPacketWithConfig(packet: ByteArray, config: SpoofConfig): List<ByteArray> {
        return splitPacket(
            packet = packet,
            strategy = config.fragmentStrategy,
            chunkSize = config.chunkSize,
            fragmentCount = config.fragmentCount,
            byteRangeSpec = config.byteRangeSpec,
            sniOffsetShift = config.sniOffsetShift
        )
    }

    /**
     * Splits a packet into TCP segments according to [strategy], supporting specific
     * byte-range definitions ([byteRangeSpec]) and SNI boundary shifts ([sniOffsetShift]).
     */
    fun splitPacket(
        packet: ByteArray,
        strategy: String,
        chunkSize: Int = 24,
        fragmentCount: Int = 4,
        byteRangeSpec: String = "1-5, 8-24, 32-64",
        sniOffsetShift: Int = 2
    ): List<ByteArray> {
        if (packet.size <= 5) return listOf(packet)

        return when (strategy) {
            "byte_range" -> {
                splitByByteRangeSpec(
                    packet = packet,
                    byteRangeSpec = byteRangeSpec,
                    sniOffsetShift = sniOffsetShift
                )
            }

            "sni_ext_boundary" -> {
                val loc = locateSni(packet)
                if (loc == null) {
                    splitByByteRangeSpec(packet, byteRangeSpec, sniOffsetShift)
                } else {
                    val shift = sniOffsetShift.coerceIn(1, (loc.hostLength - 1).coerceAtLeast(1))
                    val sniCut = (loc.hostStartOffset + shift).coerceIn(1, packet.size - 1)
                    val sniEnd = (loc.hostStartOffset + loc.hostLength).coerceIn(sniCut, packet.size)
                    val points = listOf(
                        0,
                        5.coerceAtMost(packet.size),
                        loc.extStartOffset.coerceIn(5, packet.size),
                        loc.hostStartOffset.coerceIn(5, packet.size),
                        sniCut,
                        sniEnd,
                        packet.size
                    ).distinct().sorted()
                    points.zipWithNext { a, b -> packet.copyOfRange(a, b) }.filter { it.isNotEmpty() }
                }
            }

            "sni_split" -> {
                val cut = if (sniOffsetShift > 0) {
                    findSniShiftOffset(packet, sniOffsetShift)
                } else {
                    findSniMidpointOffset(packet)
                }
                listOf(
                    packet.copyOfRange(0, cut),
                    packet.copyOfRange(cut, packet.size)
                )
            }

            "sni_multi" -> {
                val loc = locateSni(packet)
                if (loc == null) {
                    splitPacket(packet, "chunk", chunkSize = 16)
                } else {
                    val out = mutableListOf<ByteArray>()
                    if (loc.hostStartOffset > 0) {
                        out.add(packet.copyOfRange(0, loc.hostStartOffset))
                    }
                    val step = sniOffsetShift.coerceIn(1, 6)
                    var cursor = loc.hostStartOffset
                    val sniEnd = (loc.hostStartOffset + loc.hostLength).coerceAtMost(packet.size)
                    while (cursor < sniEnd) {
                        val next = (cursor + step).coerceAtMost(sniEnd)
                        out.add(packet.copyOfRange(cursor, next))
                        cursor = next
                    }
                    if (sniEnd < packet.size) {
                        out.add(packet.copyOfRange(sniEnd, packet.size))
                    }
                    out
                }
            }

            "tls_header_and_sni" -> {
                val mid = findSniShiftOffset(packet, sniOffsetShift)
                if (mid > 6) {
                    listOf(
                        packet.copyOfRange(0, 5),
                        packet.copyOfRange(5, mid),
                        packet.copyOfRange(mid, packet.size)
                    )
                } else {
                    listOf(
                        packet.copyOfRange(0, 5),
                        packet.copyOfRange(5, packet.size)
                    )
                }
            }

            "middle" -> {
                val half = (packet.size / 2).coerceAtLeast(1)
                listOf(
                    packet.copyOfRange(0, half),
                    packet.copyOfRange(half, packet.size)
                )
            }

            "random" -> {
                val targetPieces = fragmentCount.coerceIn(2, 16)
                val cutPoints = sortedSetOf<Int>()
                cutPoints.add(findSniShiftOffset(packet, sniOffsetShift))
                var attempts = 0
                while (cutPoints.size < targetPieces - 1 && attempts < 32 && packet.size > 16) {
                    cutPoints.add(Random.nextInt(5, packet.size - 1))
                    attempts++
                }
                val points = listOf(0) + cutPoints.toList() + listOf(packet.size)
                points.zipWithNext { a, b -> packet.copyOfRange(a, b) }.filter { it.isNotEmpty() }
            }

            "chunk" -> {
                val step = chunkSize.coerceIn(4, 256)
                val out = mutableListOf<ByteArray>()
                var offset = 0
                while (offset < packet.size) {
                    val end = (offset + step).coerceAtMost(packet.size)
                    out.add(packet.copyOfRange(offset, end))
                    offset = end
                }
                out
            }

            else -> {
                val mid = findSniMidpointOffset(packet)
                listOf(
                    packet.copyOfRange(0, mid),
                    packet.copyOfRange(mid, packet.size)
                )
            }
        }
    }

    /**
     * Parses and executes a specific byte-range specification [byteRangeSpec] across [packet].
     *
     * Supported syntax examples:
     * - Range lengths per fragment: `"1-5, 8-24, 32-64"` or `"10-20"` (repeats last range until end)
     * - SNI-anchor token: `"2-6, sni, 16-32"` (cuts at TLS header, then right inside the SNI at `sniOffsetShift`, then 16-32B chunks)
     * - Explicit ascending byte offsets: `"5, 16, 36, 72"` (cuts packet at exact byte indices 5, 16, 36, 72, plus SNI anchor)
     */
    fun splitByByteRangeSpec(
        packet: ByteArray,
        byteRangeSpec: String,
        sniOffsetShift: Int = 2
    ): List<ByteArray> {
        if (packet.size <= 5) return listOf(packet)
        val rawTokens = byteRangeSpec
            .split(',', ';')
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }

        val sniAnchor = findSniShiftOffset(packet, sniOffsetShift)

        if (rawTokens.isEmpty()) {
            return splitByByteRangeSpec(packet, "1-5, 8-24, 32-64", sniOffsetShift)
        }

        // Case A: Explicit ascending byte-offset cut list (e.g. "5, 16, 36, 72")
        val allPlainInts = rawTokens.mapNotNull { it.toIntOrNull() }
        if (allPlainInts.size == rawTokens.size &&
            allPlainInts.size >= 2 &&
            allPlainInts.zipWithNext().all { (a, b) -> b > a }
        ) {
            val cutPoints = sortedSetOf(0, packet.size)
            allPlainInts.forEach { pt ->
                if (pt in 1 until packet.size) cutPoints.add(pt)
            }
            if (sniAnchor in 1 until packet.size) {
                cutPoints.add(sniAnchor)
            }
            return cutPoints.toList()
                .zipWithNext { a, b -> packet.copyOfRange(a, b) }
                .filter { it.isNotEmpty() }
        }

        // Case B: Sequential byte-range length rules (e.g. "1-5, 8-24, 32-64" or "2-6, sni, 16-32")
        val segments = mutableListOf<ByteArray>()
        var cursor = 0
        var tokenIndex = 0
        var safety = 0

        while (cursor < packet.size && safety < 512) {
            safety++
            val token = rawTokens[tokenIndex.coerceAtMost(rawTokens.lastIndex)]
            if (tokenIndex < rawTokens.lastIndex) {
                tokenIndex++
            }

            val nextCursor = when {
                token.startsWith("sni") -> {
                    val customShift = token.removePrefix("sni").removePrefix("+").trim().toIntOrNull()
                    val anchor = if (customShift != null && customShift > 0) {
                        findSniShiftOffset(packet, customShift)
                    } else {
                        sniAnchor
                    }
                    if (cursor < anchor) {
                        anchor
                    } else {
                        (cursor + sniOffsetShift.coerceIn(2, 16)).coerceAtMost(packet.size)
                    }
                }
                token.contains('-') -> {
                    val parts = token.split('-', limit = 2)
                    val minB = (parts.getOrNull(0)?.trim()?.toIntOrNull() ?: 8).coerceIn(1, 4096)
                    val maxB = (parts.getOrNull(1)?.trim()?.toIntOrNull() ?: minB).coerceIn(minB, 4096)
                    val chosenLen = if (maxB > minB) Random.nextInt(minB, maxB + 1) else minB
                    val candidate = (cursor + chosenLen).coerceAtMost(packet.size)
                    // Guarantee that if this segment spans across the SNI shift anchor, we cut at the SNI anchor first
                    if (cursor < sniAnchor && candidate > sniAnchor) {
                        sniAnchor
                    } else {
                        candidate
                    }
                }
                else -> {
                    val fixedLen = (token.toIntOrNull() ?: 24).coerceIn(1, 4096)
                    val candidate = (cursor + fixedLen).coerceAtMost(packet.size)
                    if (cursor < sniAnchor && candidate > sniAnchor) {
                        sniAnchor
                    } else {
                        candidate
                    }
                }
            }

            val safeNext = nextCursor.coerceIn(cursor + 1, packet.size)
            segments.add(packet.copyOfRange(cursor, safeNext))
            cursor = safeNext
        }

        if (cursor < packet.size) {
            segments.add(packet.copyOfRange(cursor, packet.size))
        }
        return segments
    }

    /**
     * Computes the next inter-fragment delay in milliseconds from [delayRangeSpec]
     * (e.g., `"5-15"` -> random `5..15` ms) or falls back to [fallbackDelayMs].
     */
    fun computeNextDelayMs(delayRangeSpec: String, fallbackDelayMs: Int): Long {
        val cleaned = delayRangeSpec.trim()
        if (cleaned.contains('-')) {
            val parts = cleaned.split('-', limit = 2)
            val minD = parts.getOrNull(0)?.trim()?.toLongOrNull()
            val maxD = parts.getOrNull(1)?.trim()?.toLongOrNull()
            if (minD != null && maxD != null && maxD >= minD && minD >= 0L) {
                val lo = minD.coerceAtMost(1000L)
                val hi = maxD.coerceIn(lo, 1000L)
                return if (hi > lo) Random.nextLong(lo, hi + 1L) else lo
            }
        }
        val single = cleaned.toLongOrNull()
        return (single ?: fallbackDelayMs.toLong()).coerceIn(0L, 1000L)
    }

    /**
     * Splits a single TLS ClientHello record (`0x16 0x03 0x01/0x03 <len> <payload>`)
     * into multiple valid TLS Record frames split across the SNI hostname or byte-range rules.
     */
    fun splitIntoMultipleTlsRecords(
        packet: ByteArray,
        strategy: String,
        chunkSize: Int,
        byteRangeSpec: String = "1-5, 8-24, 32-64",
        sniOffsetShift: Int = 2
    ): ByteArray {
        if (!isTlsClientHello(packet)) return packet
        val recordLen = readUInt16(packet, 3)
        if (5 + recordLen != packet.size) return packet

        val contentType = packet[0]
        val versionMajor = packet[1]
        val versionMinor = packet[2]
        val body = packet.copyOfRange(5, packet.size)

        val loc = locateSni(packet)
        val bodySplitPoints = when {
            strategy == "byte_range" -> {
                val slices = splitByByteRangeSpec(body, byteRangeSpec, sniOffsetShift)
                val pts = mutableListOf(0)
                var acc = 0
                slices.forEach { s ->
                    acc += s.size
                    pts.add(acc)
                }
                pts.distinct().sorted()
            }
            loc != null -> {
                val sniBodyStart = (loc.hostStartOffset - 5).coerceIn(1, body.size - 1)
                val shift = sniOffsetShift.coerceIn(1, (loc.hostLength - 1).coerceAtLeast(1))
                val sniBodyCut = (sniBodyStart + shift).coerceIn(sniBodyStart, body.size - 1)
                listOf(0, sniBodyStart, sniBodyCut, body.size).distinct().sorted()
            }
            strategy == "chunk" -> {
                val step = chunkSize.coerceIn(16, 256)
                val pts = mutableListOf(0)
                var cur = step
                while (cur < body.size) {
                    pts.add(cur)
                    cur += step
                }
                pts.add(body.size)
                pts
            }
            else -> {
                val half = (body.size / 2).coerceAtLeast(1)
                listOf(0, half, body.size)
            }
        }

        val out = ByteArrayOutputStream(packet.size + 32)
        bodySplitPoints.zipWithNext { start, end ->
            val len = end - start
            if (len > 0) {
                out.write(contentType.toInt())
                out.write(versionMajor.toInt())
                out.write(versionMinor.toInt())
                out.write((len ushr 8) and 0xFF)
                out.write(len and 0xFF)
                out.write(body, start, len)
            }
        }
        return out.toByteArray()
    }

    /**
     * Rewrites the `server_name` extension inside a TLS ClientHello record to [newSni]
     * while preserving valid TLS record/handshake/extension lengths.
     */
    fun rewriteClientHelloSni(packet: ByteArray, newSni: String): ByteArray {
        val loc = locateSni(packet) ?: return packet
        val cleanSniBytes = newSni.trim().toByteArray(StandardCharsets.US_ASCII)
        if (cleanSniBytes.isEmpty()) return packet

        val oldLen = loc.hostLength
        val newLen = cleanSniBytes.size
        val delta = newLen - oldLen

        val recordPayloadLen = readUInt16(packet, 3)
        if (5 + recordPayloadLen != packet.size) return packet

        val handshakeLen = ((packet[6].toInt() and 0xFF) shl 16) or
            ((packet[7].toInt() and 0xFF) shl 8) or
            (packet[8].toInt() and 0xFF)

        var pos = 5 + 4 + 2 + 32
        val sessionIdLen = packet[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        val cipherLen = readUInt16(packet, pos)
        pos += 2 + cipherLen
        val compLen = packet[pos].toInt() and 0xFF
        pos += 1 + compLen
        val extTotalLenOffset = pos
        val oldExtTotalLen = readUInt16(packet, extTotalLenOffset)

        val sniExtOffset = loc.extStartOffset
        val oldSniExtLen = readUInt16(packet, sniExtOffset + 2)
        val oldSniListLen = readUInt16(packet, sniExtOffset + 4)

        val result = ByteArray(packet.size + delta)
        System.arraycopy(packet, 0, result, 0, loc.hostStartOffset)
        System.arraycopy(cleanSniBytes, 0, result, loc.hostStartOffset, newLen)
        val tailSrc = loc.hostStartOffset + oldLen
        val tailLen = packet.size - tailSrc
        if (tailLen > 0) {
            System.arraycopy(packet, tailSrc, result, loc.hostStartOffset + newLen, tailLen)
        }

        writeUInt16(result, 3, recordPayloadLen + delta)
        val newHsLen = handshakeLen + delta
        result[6] = ((newHsLen ushr 16) and 0xFF).toByte()
        result[7] = ((newHsLen ushr 8) and 0xFF).toByte()
        result[8] = (newHsLen and 0xFF).toByte()
        writeUInt16(result, extTotalLenOffset, oldExtTotalLen + delta)
        writeUInt16(result, sniExtOffset + 2, oldSniExtLen + delta)
        writeUInt16(result, sniExtOffset + 4, oldSniListLen + delta)
        writeUInt16(result, sniExtOffset + 7, newLen)

        return result
    }

    /**
     * Generates a human-readable summary of the active fragmentation & payload obfuscation pipeline.
     */
    fun describePipelineSummary(config: SpoofConfig): String {
        val parts = mutableListOf<String>()
        parts.add("method=${config.method}")
        when (config.fragmentStrategy) {
            "byte_range" -> parts.add("ranges=[${config.byteRangeSpec}] (sni_shift=+${config.sniOffsetShift}B)")
            "sni_ext_boundary" -> parts.add("sni_ext_boundary (sni_shift=+${config.sniOffsetShift}B)")
            else -> parts.add("strategy=${config.fragmentStrategy} (shift=+${config.sniOffsetShift}B)")
        }
        parts.add("delay=${config.delayRangeSpec.ifBlank { "${config.fragmentDelayMs}" }}ms")
        if (config.tlsRecordVersionCap != "keep") {
            parts.add("rec_ver=${config.tlsRecordVersionCap}")
        }
        val decoyObfuscation = buildList {
            if (config.sniCaseObfuscation != "none") add("sni_case=${config.sniCaseObfuscation}")
            if (config.tlsPaddingSize > 0) add("pad=${config.tlsPaddingSize}B")
            if (config.greaseObfuscation) add("GREASE")
        }
        if (config.method in listOf("combined", "disorder", "inject")) {
            val obf = if (decoyObfuscation.isEmpty()) "" else " [${decoyObfuscation.joinToString(",")}]"
            parts.add("decoy=${config.decoyPayloadMode}×${config.decoyRepeats}(ttl=${config.decoyTtl})$obf")
        } else if (decoyObfuscation.isNotEmpty()) {
            parts.add("obfuscation unused (decoy-only; method has no decoy)")
        }
        return parts.joinToString(" • ")
    }

    /**
     * Constructs a genuine TLS ClientHello handshake packet with [sni] as the server_name extension.
     */
    fun buildSyntheticClientHello(sni: String): ByteArray {
        val hostBytes = sni.trim().ifBlank { "cloudflare.com" }.toByteArray(StandardCharsets.US_ASCII)
        val sniExtData = ByteArrayOutputStream()
        writeUInt16(sniExtData, hostBytes.size + 3)
        sniExtData.write(0) // host_name
        writeUInt16(sniExtData, hostBytes.size)
        sniExtData.write(hostBytes)
        val sniBytes = sniExtData.toByteArray()

        val extStream = ByteArrayOutputStream()
        writeUInt16(extStream, 0x0000) // server_name
        writeUInt16(extStream, sniBytes.size)
        extStream.write(sniBytes)

        writeUInt16(extStream, 0x002B) // supported_versions
        writeUInt16(extStream, 5)
        extStream.write(4)
        extStream.write(byteArrayOf(0x03, 0x04, 0x03, 0x03))
        val allExts = extStream.toByteArray()

        val hsStream = ByteArrayOutputStream()
        hsStream.write(byteArrayOf(0x03, 0x03))
        val randomBytes = ByteArray(32) { Random.nextInt().toByte() }
        hsStream.write(randomBytes)
        hsStream.write(0) // session ID len
        hsStream.write(byteArrayOf(0x00, 0x04, 0x13, 0x01, 0xC0.toByte(), 0x2F))
        hsStream.write(byteArrayOf(0x01, 0x00)) // compression null
        val extLenBuf = ByteArray(2)
        writeUInt16(extLenBuf, 0, allExts.size)
        hsStream.write(extLenBuf)
        hsStream.write(allExts)

        val hsPayload = hsStream.toByteArray()
        val recordStream = ByteArrayOutputStream()
        recordStream.write(byteArrayOf(0x16, 0x03, 0x01))
        val totalRecordPayloadLen = 4 + hsPayload.size
        val recLenBuf = ByteArray(2)
        writeUInt16(recLenBuf, 0, totalRecordPayloadLen)
        recordStream.write(recLenBuf)

        recordStream.write(0x01)
        recordStream.write((hsPayload.size ushr 16) and 0xFF)
        recordStream.write((hsPayload.size ushr 8) and 0xFF)
        recordStream.write(hsPayload.size and 0xFF)
        recordStream.write(hsPayload)

        return recordStream.toByteArray()
    }

    private fun writeUInt16(out: OutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun readUInt16(buf: ByteArray, offset: Int): Int {
        return ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
    }

    private fun writeUInt16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }
}
