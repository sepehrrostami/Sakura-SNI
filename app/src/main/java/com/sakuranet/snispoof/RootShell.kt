package com.sakuranet.snispoof

import android.content.Context
import android.os.Build
import android.os.Process as AndroidProcess
import android.system.Os
import android.system.OsConstants
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.net.Inet6Address
import java.net.Socket
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Root, kernel socket option, and native binary helper.
 * - Implements a FileLock + SHA-256 check-then-atomic-rename strategy when preparing
 *   the `sakura-sni` binary in the app's internal files directory to prevent `ETXTBSY`.
 * - Sets low `IP_TTL` on decoy sockets via `android.system.Os.setsockoptInt`.
 * - Configures high-priority Android policy routing (`ip rule pref 5000..5002`) using the
 *   active physical interface (`wlan0`, `rmnet_dataX`) from `/data/misc/net/rt_tables` so
 *   outbound connections to the CDN edge IP never loop into `tun0` (v2rayNG VPN mode).
 */
object RootShell {

    private val prepLock = Any()

    @Volatile
    private var lastProcess: Process? = null

    @Volatile
    private var cachedAssetSha256: String? = null

    fun isRootAvailable(): Boolean = try {
        val p = ProcessBuilder("su", "-c", "id")
            .redirectErrorStream(true)
            .start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor(3, TimeUnit.SECONDS)
        out.contains("uid=0")
    } catch (_: Exception) {
        false
    }

    fun isArm64Supported(): Boolean =
        Build.SUPPORTED_ABIS.any { it == "arm64-v8a" }

    fun deviceAbiSummary(): String =
        Build.SUPPORTED_ABIS.joinToString(", ")

    /**
     * Sets a low IPv4/IPv6 TTL (`IP_TTL` / `IPV6_UNICAST_HOPS`) on [socket] so decoy
     * ClientHello packets expire at the ISP DPI middlebox before reaching the CDN edge.
     * Call it after `connect()` (the fd exists and the handshake already used the normal TTL).
     * Returns true only if the option was actually applied.
     */
    fun trySetSocketLowTtl(socket: Socket, ttl: Int): Boolean {
        val safeTtl = ttl.coerceIn(1, 64)
        return try {
            val fd = extractSocketFileDescriptor(socket) ?: return false
            if (socket.inetAddress is Inet6Address) {
                Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, safeTtl)
            } else {
                Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, safeTtl)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Attempts kernel-level `SO_BINDTODEVICE` on [socket] to [iface] (e.g. `wlan0`, `rmnet_data0`)
     * as an extra layer alongside `Network.bindSocket(socket)`.
     */
    fun tryBindSocketToDevice(socket: Socket, iface: String): Boolean {
        val cleanIface = iface.trim()
        if (cleanIface.isBlank() || cleanIface.startsWith("tun", ignoreCase = true)) return false
        return try {
            // Ensure underlying SocketImpl/FD exists before extracting
            runCatching { socket.reuseAddress }
            val fd = extractSocketFileDescriptor(socket) ?: return false
            val m = Os::class.java.getMethod(
                "setsockoptIfreq",
                FileDescriptor::class.java,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                String::class.java
            )
            m.invoke(null, fd, OsConstants.SOL_SOCKET, OsConstants.SO_BINDTODEVICE, cleanIface)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun extractSocketFileDescriptor(socket: Socket): FileDescriptor? {
        // Android's libcore exposes Socket.getFileDescriptor$() (used by the framework itself)
        runCatching {
            val m = Socket::class.java.getMethod("getFileDescriptor\$")
            (m.invoke(socket) as? FileDescriptor)?.let { if (it.valid()) return it }
        }
        return try {
            val implField = Socket::class.java.getDeclaredField("impl").apply { isAccessible = true }
            val socketImpl = implField.get(socket) ?: return null
            val fdField = java.net.SocketImpl::class.java.getDeclaredField("fd").apply { isAccessible = true }
            fdField.get(socketImpl) as? FileDescriptor
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Prepares the bundled `sakura-sni` binary in [destDir] using:
     * 1. Process & Cross-Process File Locking (`sakura-sni.lock` via NIO FileChannel.lock).
     * 2. Check-Before-Write (SHA-256 verification).
     * 3. Stage-Unlink-Atomic-Rename to prevent `ETXTBSY (Text file busy)`.
     */
    fun installBinary(context: Context, destDir: File): File = synchronized(prepLock) {
        destDir.mkdirs()
        val lockFile = File(destDir, "sakura-sni.lock")

        RandomAccessFile(lockFile, "rw").use { raf ->
            val channel = raf.channel
            val fileLock = try {
                channel.lock()
            } catch (_: Exception) {
                null
            }
            try {
                prepareBinaryLocked(context, destDir)
            } finally {
                try {
                    fileLock?.release()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun prepareBinaryLocked(context: Context, destDir: File): File {
        val targetFile = File(destDir, "sakura-sni")
        val assetSha = getBundledAssetSha256(context)

        if (targetFile.exists() && targetFile.length() > 0L) {
            val existingSha = runCatching { computeFileSha256(targetFile) }.getOrNull()
            if (existingSha != null && existingSha == assetSha) {
                targetFile.setExecutable(true, /* ownerOnly = */ false)
                targetFile.setReadable(true, /* ownerOnly = */ false)
                cleanupStaleStagingFiles(destDir, keepFile = null)
                return targetFile
            }
        }

        val stageFile = File(destDir, "sakura-sni.stage.${System.nanoTime()}")
        context.assets.open("arm64-v8a/sakura-sni").use { input ->
            FileOutputStream(stageFile).use { fos ->
                input.copyTo(fos)
                fos.flush()
                runCatching { fos.fd.sync() }
            }
        }
        stageFile.setExecutable(true, /* ownerOnly = */ false)
        stageFile.setReadable(true, /* ownerOnly = */ false)

        val replaced = tryAtomicReplace(stageFile, targetFile)
        return if (replaced && targetFile.exists() && targetFile.length() > 0L) {
            targetFile.setExecutable(true, /* ownerOnly = */ false)
            targetFile.setReadable(true, /* ownerOnly = */ false)
            cleanupStaleStagingFiles(destDir, keepFile = null)
            targetFile
        } else {
            cleanupStaleStagingFiles(destDir, keepFile = stageFile)
            stageFile
        }
    }

    private fun tryAtomicReplace(stageFile: File, targetFile: File): Boolean {
        return try {
            if (targetFile.exists()) {
                targetFile.delete()
            }
            try {
                Files.move(
                    stageFile.toPath(),
                    targetFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
                true
            } catch (_: Exception) {
                stageFile.renameTo(targetFile)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun cleanupStaleStagingFiles(destDir: File, keepFile: File?) {
        try {
            destDir.listFiles()?.forEach { file ->
                val isStale = file.name.startsWith("sakura-sni.stage.") ||
                    file.name.startsWith("sakura-sni-bin-") ||
                    file.name.startsWith("sakura-sni.tmp")
                if (isStale && (keepFile == null || file.absolutePath != keepFile.absolutePath)) {
                    file.delete()
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun getBundledAssetSha256(context: Context): String {
        cachedAssetSha256?.let { return it }
        val computed = context.assets.open("arm64-v8a/sakura-sni").use { computeStreamSha256(it) }
        cachedAssetSha256 = computed
        return computed
    }

    private fun computeFileSha256(file: File): String =
        file.inputStream().use { computeStreamSha256(it) }

    private fun computeStreamSha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(16 * 1024)
        var read: Int
        while (input.read(buffer).also { read = it } != -1) {
            digest.update(buffer, 0, read)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Installs high-priority policy routing rules (`pref 5000..5002`, before Android's VPN rules
     * at `10000..13000`) using the physical network interface [physicalIface] (`wlan0`, `rmnet_dataX`)
     * so upstream traffic to [connectIp] and sockets owned by this app bypass `tun0`.
     */
    fun setupVpnBypassRules(
        connectIp: String,
        physicalIface: String = "",
        appUid: Int = AndroidProcess.myUid(),
        onLine: ((String) -> Unit)? = null
    ) {
        val cleanIp = connectIp.trim().substringBefore(":")
        if (cleanIp.isBlank()) return
        val hintIface = physicalIface.trim()
        val script = """
            PHYS_IF="$hintIface"
            NET_TABLE=""
            if [ -n "${'$'}PHYS_IF" ] && [ -r /data/misc/net/rt_tables ]; then
                while read -r tid tname; do
                    if [ "${'$'}tname" = "${'$'}PHYS_IF" ]; then
                        NET_TABLE="${'$'}tid"
                        break
                    fi
                done < /data/misc/net/rt_tables
            fi
            if [ -z "${'$'}NET_TABLE" ] && [ -r /data/misc/net/rt_tables ]; then
                while read -r tid tname; do
                    case "${'$'}tname" in
                        wlan*|rmnet*|ccmni*|eth*)
                            if ip route show table "${'$'}tid" 2>/dev/null | grep -q "^default "; then
                                NET_TABLE="${'$'}tid"
                                PHYS_IF="${'$'}tname"
                                break
                            fi
                            ;;
                    esac
                done < /data/misc/net/rt_tables
            fi
            if [ -z "${'$'}NET_TABLE" ] && [ -n "${'$'}PHYS_IF" ]; then
                NET_TABLE="${'$'}PHYS_IF"
            fi
            if [ -n "${'$'}NET_TABLE" ]; then
                while ip rule del pref 5000 2>/dev/null; do :; done
                while ip rule del pref 5001 2>/dev/null; do :; done
                while ip rule del pref 5002 2>/dev/null; do :; done
                while ip rule del pref 9000 2>/dev/null; do :; done
                while ip rule del pref 9001 2>/dev/null; do :; done
                while ip rule del pref 9002 2>/dev/null; do :; done
                ip rule add pref 5000 to $cleanIp/32 lookup "${'$'}NET_TABLE" 2>/dev/null || true
                ip rule add pref 5001 uidrange $appUid-$appUid lookup "${'$'}NET_TABLE" 2>/dev/null || true
                ip rule add pref 5002 uidrange 0-0 to $cleanIp/32 lookup "${'$'}NET_TABLE" 2>/dev/null || true
                ip route flush cache 2>/dev/null || true
                echo "[route] VPN-bypass policy route active: $cleanIp -> iface=${'$'}{PHYS_IF:-phys} (table=${'$'}NET_TABLE)"
            fi
        """.trimIndent()

        try {
            val p = ProcessBuilder("su", "-c", script)
                .redirectErrorStream(true)
                .start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor(2, TimeUnit.SECONDS)
            if (out.isNotEmpty()) {
                onLine?.invoke(out)
            }
        } catch (_: Exception) {
        }
    }

    fun clearVpnBypassRules() {
        val cleanupScript = """
            while ip rule del pref 5000 2>/dev/null; do :; done
            while ip rule del pref 5001 2>/dev/null; do :; done
            while ip rule del pref 5002 2>/dev/null; do :; done
            while ip rule del pref 9000 2>/dev/null; do :; done
            while ip rule del pref 9001 2>/dev/null; do :; done
            while ip rule del pref 9002 2>/dev/null; do :; done
            ip route flush cache 2>/dev/null || true
        """.trimIndent()
        try {
            val p = ProcessBuilder("su", "-c", cleanupScript)
                .redirectErrorStream(true)
                .start()
            p.waitFor(2, TimeUnit.SECONDS)
        } catch (_: Exception) {
        }
    }

    private fun extractConnectIpFromConfig(configPath: String): String {
        return try {
            val json = JSONObject(File(configPath).readText())
            val listeners = json.optJSONArray("listeners")
            if (listeners != null && listeners.length() > 0) {
                val connect = listeners.getJSONObject(0).optString("connect", "")
                connect.substringBeforeLast(":")
                    .removePrefix("[")
                    .removeSuffix("]")
            } else {
                ""
            }
        } catch (_: Exception) {
            ""
        }
    }

    /**
     * Terminates any lingering `sakura-sni` processes (both app-UID and root-UID)
     * so the local listening port (e.g. 127.0.0.1:40443) is freed cleanly before starting.
     */
    fun killExistingInstances(useRoot: Boolean, clearRoutes: Boolean = false) {
        try {
            lastProcess?.destroyForcibly()
        } catch (_: Exception) {
        } finally {
            lastProcess = null
        }

        try {
            val p = ProcessBuilder(
                "sh",
                "-c",
                "pkill -9 -f sakura-sni || killall -9 sakura-sni || true"
            ).redirectErrorStream(true).start()
            p.waitFor(1, TimeUnit.SECONDS)
        } catch (_: Exception) {
        }

        if (useRoot) {
            try {
                val p = ProcessBuilder(
                    "su",
                    "-c",
                    "pkill -9 -f sakura-sni || killall -9 sakura-sni || true"
                ).redirectErrorStream(true).start()
                p.waitFor(2, TimeUnit.SECONDS)
            } catch (_: Exception) {
            }
            if (clearRoutes) {
                clearVpnBypassRules()
            }
        }

        try {
            Thread.sleep(120)
        } catch (_: InterruptedException) {
        }
    }

    /** POSIX single-quote escaping: `it's` -> `'it'\''s'`. */
    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun extractBinaryEnvFromConfig(configPath: String): Map<String, String> {
        val env = linkedMapOf<String, String>()
        try {
            val json = JSONObject(File(configPath).readText())
            val listeners = json.optJSONArray("listeners")
            val l0 = if (listeners != null && listeners.length() > 0) listeners.getJSONObject(0) else null
            if (l0 != null) {
                // Keys must match what SpoofConfig.toJsonString() writes
                // ("fragmentation" / "obfuscation" objects and their *_spec / *_size / *_obfuscation names).
                env["SAKURA_METHOD"] = l0.optString("method", "combined")
                env["SAKURA_FAKE_SNI"] = l0.optString("fake_sni", "")
                l0.optJSONObject("fragmentation")?.let { frag ->
                    env["SAKURA_FRAGMENT_STRATEGY"] = frag.optString("strategy", "byte_range")
                    env["SAKURA_BYTE_RANGE"] = frag.optString("byte_range_spec", "1-5, 8-24, 32-64")
                    env["SAKURA_DELAY_RANGE"] = frag.optString("delay_range_spec", "5-15")
                    env["SAKURA_SNI_SHIFT"] = frag.optInt("sni_offset_shift", 2).toString()
                    env["SAKURA_CHUNK_SIZE"] = frag.optInt("chunk_size", 24).toString()
                    env["SAKURA_FRAGMENT_COUNT"] = frag.optInt("fragment_count", 4).toString()
                }
                l0.optJSONObject("obfuscation")?.let { obf ->
                    env["SAKURA_SNI_CASE"] = obf.optString("sni_case_obfuscation", "none")
                    env["SAKURA_TLS_PADDING"] = obf.optInt("tls_padding_size", 0).toString()
                    env["SAKURA_GREASE"] = if (obf.optBoolean("grease_obfuscation", false)) "1" else "0"
                    env["SAKURA_RECORD_VERSION_CAP"] = obf.optString("tls_record_version_cap", "keep")
                    env["SAKURA_DECOY_MODE"] = obf.optString("decoy_payload_mode", "fake_client_hello")
                    env["SAKURA_DECOY_REPEATS"] = obf.optInt("decoy_repeats", 1).toString()
                    env["SAKURA_DECOY_TTL"] = obf.optInt("decoy_ttl", 4).toString()
                }
            }
        } catch (_: Exception) {
        }
        return env
    }

    /**
     * Launches `sakura-sni` with the given [configPath], injecting extended byte-range
     * fragmentation and payload obfuscation environment variables alongside `config.json`.
     */
    fun runBinary(
        context: Context,
        binPath: String,
        configPath: String,
        useRoot: Boolean,
        onLine: (String) -> Unit,
        onExit: (Int) -> Unit = {}
    ): Process? {
        killExistingInstances(useRoot, clearRoutes = false)

        val targetIp = extractConnectIpFromConfig(configPath)
        val extraEnv = extractBinaryEnvFromConfig(configPath)
        val appUid = AndroidProcess.myUid()
        val physIface = NetworkTools.findPhysicalUnderlyingNetwork(context)?.second.orEmpty()
        if (useRoot && targetIp.isNotBlank()) {
            setupVpnBypassRules(targetIp, physIface, appUid, onLine)
        }

        // Single-quote every value for the root shell: inside double quotes `$(...)`, backticks and
        // `$VAR` in a user-typed field (e.g. the Fake SNI) would still be expanded/executed as root.
        val envExports = extraEnv.entries.joinToString(" ") { (k, v) -> "$k=${shellQuote(v)}" }
        val execPart = "exec ${shellQuote(binPath)} -config ${shellQuote(configPath)}"
        val cmdString = if (envExports.isNotBlank()) {
            "export $envExports; $execPart"
        } else {
            execPart
        }

        // Android 10+ (W^X) forbids an app from exec()-ing files in its own data dir, so the
        // binary copied to filesDir can only be started through su there.
        val unprivilegedExecBlocked = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
        if (!useRoot && unprivilegedExecBlocked) {
            onLine("[error] Native sakura-sni needs root on Android 10+ (apps cannot exec files from their data dir). Use the VPN-Safe Kotlin engine instead.")
            onExit(-1)
            return null
        }

        val proc: Process = try {
            if (useRoot) {
                try {
                    ProcessBuilder("su", "-c", cmdString)
                        .apply { environment().putAll(extraEnv) }
                        .redirectErrorStream(true)
                        .start()
                } catch (suErr: Exception) {
                    if (unprivilegedExecBlocked) throw suErr
                    onLine("[warn] su execution failed (${suErr.message}); falling back to unprivileged process...")
                    ProcessBuilder(binPath, "-config", configPath)
                        .apply { environment().putAll(extraEnv) }
                        .redirectErrorStream(true)
                        .start()
                }
            } else {
                ProcessBuilder(binPath, "-config", configPath)
                    .apply { environment().putAll(extraEnv) }
                    .redirectErrorStream(true)
                    .start()
            }
        } catch (e: Exception) {
            val abiNote = if (!isArm64Supported()) {
                " (Device ABIs: ${deviceAbiSummary()} — bundled sakura-sni binary is compiled for arm64-v8a)"
            } else {
                ""
            }
            onLine("[error] Failed to launch sakura-sni binary: ${e.message}$abiNote")
            onExit(-1)
            return null
        }

        lastProcess = proc

        if (useRoot && targetIp.isNotBlank()) {
            Thread {
                while (lastProcess === proc) {
                    try {
                        Thread.sleep(5000)
                        if (lastProcess === proc) {
                            val latestIface = NetworkTools.findPhysicalUnderlyingNetwork(context)?.second.orEmpty()
                            setupVpnBypassRules(targetIp, latestIface, appUid, onLine = null)
                        }
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            }.apply { isDaemon = true }.start()
        }

        Thread {
            try {
                BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        onLine(line ?: "")
                    }
                }
            } catch (_: Exception) {
            } finally {
                val code = try {
                    proc.waitFor()
                } catch (_: InterruptedException) {
                    -1
                }
                if (lastProcess === proc) {
                    lastProcess = null
                }
                onExit(code)
            }
        }.apply { isDaemon = true }.start()

        return proc
    }
}
