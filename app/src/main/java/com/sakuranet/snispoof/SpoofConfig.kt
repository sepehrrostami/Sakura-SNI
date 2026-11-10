package com.sakuranet.snispoof

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

data class SpoofMethodMeta(
    val id: String,
    val title: String,
    val badge: String,
    val description: String
)

data class FragmentStrategyMeta(
    val id: String,
    val title: String,
    val subtitle: String
)

data class ObfuscationOptionMeta(
    val id: String,
    val title: String,
    val subtitle: String
)

/**
 * Full configuration for both the built-in VPN-Safe Multi-Method Engine ([SakuraProxyEngine])
 * and the bundled `sakura-sni` binary, including advanced byte-range splitting and
 * TLS ClientHello payload obfuscation parameters.
 */
data class SpoofConfig(
    val listenPort: Int = 40443,
    val connectIp: String = "",
    val connectPort: Int = 443,
    val fakeSni: String = "speed.cloudflare.com",
    val method: String = "combined",
    val fragmentStrategy: String = "sni_split",
    val fragmentDelayMs: Int = 10,
    val handshakeTimeoutMs: Int = 2500,
    val connectTimeoutMs: Int = 5000,
    val logLevel: String = "info",
    val engineMode: String = "vpn_safe_kotlin", // vpn_safe_kotlin | native_binary
    val bypassVpnTun: Boolean = true,
    val decoyTtl: Int = 4,
    val chunkSize: Int = 24,
    val fragmentCount: Int = 4,
    val tcpNoDelay: Boolean = true,
    // Advanced Byte-Range Splitting parameters
    val byteRangeSpec: String = "1-5, 8-24, 32-64",
    val delayRangeSpec: String = "5-15",
    val sniOffsetShift: Int = 2,
    // Payload Obfuscation parameters
    val sniCaseObfuscation: String = "none", // none | alternating | random_mixed | upper_tld
    val tlsPaddingSize: Int = 0, // 0..2048 bytes (RFC 7685 ext 0x0015)
    val greaseObfuscation: Boolean = false, // RFC 8701 GREASE extension injection
    val tlsRecordVersionCap: String = "keep", // keep | tls10_0301 | tls12_0303
    val decoyPayloadMode: String = "fake_client_hello", // fake_client_hello | random_noise | zero_padded_hello | http_get_decoy
    val decoyRepeats: Int = 1
) {
    /**
     * Maps extended methods to the 3 methods understood by the external Go binary
     * when running in `native_binary` mode.
     */
    fun binaryCompatibleMethod(): String = when (method) {
        "combined", "disorder" -> "combined"
        "inject" -> "inject"
        else -> "fragment"
    }

    fun binaryCompatibleStrategy(): String = when (fragmentStrategy) {
        "sni_split", "sni_multi", "tls_header_and_sni", "sni_ext_boundary" -> "sni_split"
        "middle" -> "middle"
        "random", "byte_range" -> "random"
        "chunk" -> "chunk"
        else -> "sni_split"
    }

    fun toJsonString(indent: Int = 2): String {
        val safeListenPort = listenPort.coerceIn(1, 65535)
        val safeConnectPort = connectPort.coerceIn(1, 65535)
        val formattedHost = if (connectIp.contains(":") && !connectIp.startsWith("[")) {
            "[$connectIp]"
        } else {
            connectIp.trim()
        }

        val fragmentationObj = JSONObject()
            .put("strategy", fragmentStrategy)
            .put("byte_range_spec", byteRangeSpec.trim())
            .put("delay_range_spec", delayRangeSpec.trim())
            .put("sni_offset_shift", sniOffsetShift.coerceIn(-64, 64))
            .put("chunk_size", chunkSize.coerceIn(2, 512))
            .put("fragment_count", fragmentCount.coerceIn(2, 32))
            .put("fragment_delay_ms", fragmentDelayMs.coerceIn(0, 2000))
            .put("tcp_no_delay", tcpNoDelay)

        val obfuscationObj = JSONObject()
            .put("sni_case_obfuscation", sniCaseObfuscation)
            .put("tls_padding_size", tlsPaddingSize.coerceIn(0, 2048))
            .put("grease_obfuscation", greaseObfuscation)
            .put("tls_record_version_cap", tlsRecordVersionCap)
            .put("decoy_payload_mode", decoyPayloadMode)
            .put("decoy_ttl", decoyTtl.coerceIn(1, 64))
            .put("decoy_repeats", decoyRepeats.coerceIn(1, 5))

        val listener = JSONObject()
            .put("listen", "127.0.0.1:$safeListenPort")
            .put("connect", "$formattedHost:$safeConnectPort")
            .put("fake_sni", fakeSni.trim())
            .put("method", binaryCompatibleMethod())
            .put("spoof_method_full", method)
            .put("fragment_strategy", binaryCompatibleStrategy())
            .put("fragment_strategy_full", fragmentStrategy)
            .put("fragment_delay_ms", fragmentDelayMs.coerceIn(0, 2000))
            .put("handshake_timeout_ms", handshakeTimeoutMs.coerceIn(250, 30000))
            .put("connect_timeout_ms", connectTimeoutMs.coerceIn(500, 30000))
            .put("engine_mode", engineMode)
            .put("bypass_vpn_tun", bypassVpnTun)
            .put("decoy_ttl", decoyTtl.coerceIn(1, 64))
            .put("chunk_size", chunkSize.coerceIn(2, 512))
            .put("fragment_count", fragmentCount.coerceIn(2, 32))
            .put("tcp_no_delay", tcpNoDelay)
            .put("byte_range_spec", byteRangeSpec.trim())
            .put("delay_range_spec", delayRangeSpec.trim())
            .put("sni_offset_shift", sniOffsetShift.coerceIn(-64, 64))
            .put("sni_case_obfuscation", sniCaseObfuscation)
            .put("tls_padding_size", tlsPaddingSize.coerceIn(0, 2048))
            .put("grease_obfuscation", greaseObfuscation)
            .put("tls_record_version_cap", tlsRecordVersionCap)
            .put("decoy_payload_mode", decoyPayloadMode)
            .put("decoy_repeats", decoyRepeats.coerceIn(1, 5))
            .put("fragmentation", fragmentationObj)
            .put("obfuscation", obfuscationObj)

        val root = JSONObject()
            .put("listeners", JSONArray().put(listener))
            .put("log_level", logLevel)
            .put("graceful_shutdown_ms", 1500)
        return root.toString(indent)
    }

    fun writeTo(file: File) {
        val parent = file.parentFile
        parent?.mkdirs()
        val stageFile = File(parent ?: file.absoluteFile.parentFile, "${file.name}.tmp.${System.nanoTime()}")
        try {
            stageFile.writeText(toJsonString(2))
            if (file.exists()) {
                file.delete()
            }
            if (!stageFile.renameTo(file)) {
                file.writeText(toJsonString(2))
                stageFile.delete()
            }
        } catch (_: Exception) {
            stageFile.delete()
            file.writeText(toJsonString(2))
        }
    }

    companion object {
        val DEFAULT_CLEAN_SNIS = listOf(
            "speed.cloudflare.com",
            "www.hcaptcha.com",
            "d1.awsstatic.com",
            "static.cloudflareinsights.com",
            "www.gstatic.com",
            "discord.com",
            "cdnjs.cloudflare.com",
            "ajax.googleapis.com",
            "fonts.googleapis.com",
            "challenges.cloudflare.com"
        )

        val BYTE_RANGE_PRESETS = listOf(
            "1-5, 8-24, 32-64",
            "1-3, 4-12, 16-48",
            "5, 16, 36, 72",
            "2-6, sni, 16-32",
            "10-20",
            "1-2, 2-4, 4-8, 8-16"
        )

        val METHOD_METAS = listOf(
            SpoofMethodMeta(
                id = "combined",
                title = "Combined (Decoy + Split)",
                badge = "VPN-Safe • Best",
                description = "Sends low-TTL decoy ClientHello with Fake SNI + splits real ClientHello across TCP segments."
            ),
            SpoofMethodMeta(
                id = "fragment",
                title = "TCP Fragment",
                badge = "No-Root • Fast",
                description = "Splits TLS ClientHello across delayed TCP segments using byte-range or SNI-aware offsets."
            ),
            SpoofMethodMeta(
                id = "tls_record",
                title = "TLS Record Split",
                badge = "No-Root • RFC",
                description = "Slices a single ClientHello handshake into multiple valid TLS Record layer frames at the SNI."
            ),
            SpoofMethodMeta(
                id = "disorder",
                title = "TTL Disorder Desync",
                badge = "DPI Evasion",
                description = "Combines low-TTL Fake SNI decoy, multi-TLS record framing, and jittered TCP segmentation."
            ),
            SpoofMethodMeta(
                id = "oob",
                title = "TCP OOB Urgent",
                badge = "Desync",
                description = "Injects a 1-byte TCP Out-of-Band urgent byte inside the SNI field (discarded by TLS server, confuses DPI)."
            ),
            // "sni_rewrite" was removed: rewriting the real ClientHello's SNI breaks the TLS
            // transcript hash, so the handshake can never complete. Old configs are migrated
            // to "combined" in ProfileStore.parseConfigJson.
            SpoofMethodMeta(
                id = "inject",
                title = "Decoy Inject Only",
                badge = "Low-TTL Decoy",
                description = "Sends a fake ClientHello carrying Fake SNI with low TTL prior to forwarding the real stream."
            )
        )

        val STRATEGY_METAS = listOf(
            FragmentStrategyMeta("sni_split", "SNI Midpoint", "Exact split inside SNI domain"),
            FragmentStrategyMeta("byte_range", "Byte-Range Split", "Custom byte ranges / cut offsets"),
            FragmentStrategyMeta("sni_multi", "SNI Micro-Slice", "Slices SNI every 2-3 bytes"),
            FragmentStrategyMeta("sni_ext_boundary", "SNI Ext Boundary", "Cuts at 0x0000 ext + SNI offset"),
            FragmentStrategyMeta("tls_header_and_sni", "Header + SNI", "5B TLS header + SNI cut"),
            FragmentStrategyMeta("middle", "50/50 Middle", "Two equal half segments"),
            FragmentStrategyMeta("random", "Random Multi", "Multi-piece random cuts"),
            FragmentStrategyMeta("chunk", "Fixed Chunks", "Uniform N-byte segments")
        )

        val SNI_CASE_MODES = listOf(
            ObfuscationOptionMeta("none", "Original Case", "Keep lowercase SNI"),
            ObfuscationOptionMeta("alternating", "aLtErNaTiNg", "Alternating ASCII case"),
            ObfuscationOptionMeta("random_mixed", "rAnDoM MiXeD", "Randomized mixed case"),
            ObfuscationOptionMeta("upper_tld", "domain.COM", "Uppercase TLD / labels")
        )

        val DECOY_PAYLOAD_MODES = listOf(
            ObfuscationOptionMeta("fake_client_hello", "Fake ClientHello", "Valid TLS ClientHello with Fake SNI"),
            ObfuscationOptionMeta("zero_padded_hello", "Padded ClientHello", "Fake SNI + RFC 7685 zero padding"),
            ObfuscationOptionMeta("random_noise", "Entropy Noise", "High-entropy obfuscated TLS frame"),
            ObfuscationOptionMeta("http_get_decoy", "HTTP GET Decoy", "Benign HTTP Host: Fake SNI header")
        )

        val TLS_RECORD_VERSION_CAPS = listOf(
            ObfuscationOptionMeta("keep", "Keep Original", "Preserve client record version"),
            ObfuscationOptionMeta("tls10_0301", "TLS 1.0 (0x0301)", "Compatibility record header"),
            ObfuscationOptionMeta("tls12_0303", "TLS 1.2 (0x0303)", "Standard TLS 1.2 record header")
        )

        val METHODS = METHOD_METAS.map { it.id }
        val FRAGMENT_STRATEGIES = STRATEGY_METAS.map { it.id }
        val LOG_LEVELS = listOf("debug", "info", "warn", "error")
    }
}

data class SavedProfile(
    val id: String,
    val name: String,
    val config: SpoofConfig
)

object ProfileStore {
    private const val PREF_NAME = "sakura_sni_prefs"
    private const val KEY_ACTIVE_CONFIG = "active_config_v3"
    private const val KEY_PROFILES = "saved_profiles_v3"

    fun loadActiveConfig(context: Context): SpoofConfig {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY_ACTIVE_CONFIG, null)
            ?: prefs.getString("active_config_v2", null)
            ?: prefs.getString("active_config_v1", null)
            ?: return SpoofConfig(
                connectIp = "104.18.4.130",
                connectPort = 443,
                listenPort = 40443,
                fakeSni = "speed.cloudflare.com",
                method = "combined",
                fragmentStrategy = "byte_range",
                byteRangeSpec = "1-5, 8-24, 32-64",
                delayRangeSpec = "5-15",
                engineMode = "vpn_safe_kotlin",
                bypassVpnTun = true
            )
        return try {
            parseConfigJson(JSONObject(raw))
        } catch (_: Exception) {
            SpoofConfig(connectIp = "104.18.4.130")
        }
    }

    fun saveActiveConfig(context: Context, config: SpoofConfig) {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_ACTIVE_CONFIG, serializeConfigJson(config).toString()).apply()
    }

    fun loadProfiles(context: Context): List<SavedProfile> {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY_PROFILES, null)
        if (raw.isNullOrBlank()) {
            val defaults = defaultProfiles()
            saveProfiles(context, defaults)
            return defaults
        }
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<SavedProfile>()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                list.add(
                    SavedProfile(
                        id = obj.optString("id", "prof_$i"),
                        name = obj.optString("name", "Profile ${i + 1}"),
                        config = parseConfigJson(obj.getJSONObject("config"))
                    )
                )
            }
            list
        } catch (_: Exception) {
            defaultProfiles()
        }
    }

    fun saveProfile(context: Context, name: String, config: SpoofConfig): List<SavedProfile> {
        val current = loadProfiles(context).toMutableList()
        val trimmedName = name.trim().ifBlank { "${config.connectIp}:${config.connectPort}" }
        val existingIdx = current.indexOfFirst { it.name.equals(trimmedName, ignoreCase = true) }
        val profile = SavedProfile(
            id = if (existingIdx >= 0) current[existingIdx].id else "prof_${System.currentTimeMillis()}",
            name = trimmedName,
            config = config
        )
        if (existingIdx >= 0) {
            current[existingIdx] = profile
        } else {
            current.add(0, profile)
        }
        saveProfiles(context, current)
        return current
    }

    fun deleteProfile(context: Context, profileId: String): List<SavedProfile> {
        val updated = loadProfiles(context).filterNot { it.id == profileId }
        saveProfiles(context, updated)
        return updated
    }

    private fun saveProfiles(context: Context, profiles: List<SavedProfile>) {
        val arr = JSONArray()
        profiles.forEach { p ->
            arr.put(
                JSONObject()
                    .put("id", p.id)
                    .put("name", p.name)
                    .put("config", serializeConfigJson(p.config))
            )
        }
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PROFILES, arr.toString())
            .apply()
    }

    private fun defaultProfiles(): List<SavedProfile> = listOf(
        SavedProfile(
            id = "preset_v2ray_byte_range_obf",
            name = "Byte-Range + Obfuscated Decoy (Best)",
            config = SpoofConfig(
                listenPort = 40443,
                connectIp = "172.66.129.89",
                connectPort = 443,
                fakeSni = "www.hcaptcha.com",
                method = "combined",
                fragmentStrategy = "byte_range",
                byteRangeSpec = "1-5, 8-24, 32-64",
                delayRangeSpec = "5-15",
                sniOffsetShift = 2,
                sniCaseObfuscation = "alternating",
                tlsPaddingSize = 256,
                greaseObfuscation = true,
                engineMode = "vpn_safe_kotlin",
                bypassVpnTun = true
            )
        ),
        SavedProfile(
            id = "preset_cf_tls_record",
            name = "Cloudflare TLS Record + Micro-SNI",
            config = SpoofConfig(
                listenPort = 40443,
                connectIp = "104.18.4.130",
                connectPort = 443,
                fakeSni = "speed.cloudflare.com",
                method = "tls_record",
                fragmentStrategy = "sni_multi",
                fragmentDelayMs = 12,
                tlsPaddingSize = 128,
                engineMode = "vpn_safe_kotlin",
                bypassVpnTun = true
            )
        ),
        SavedProfile(
            id = "preset_disorder_dpi",
            name = "ISP Deep-DPI Disorder + Grease",
            config = SpoofConfig(
                listenPort = 40443,
                connectIp = "172.66.129.89",
                connectPort = 443,
                fakeSni = "www.gstatic.com",
                method = "disorder",
                fragmentStrategy = "sni_ext_boundary",
                fragmentDelayMs = 15,
                decoyTtl = 4,
                decoyPayloadMode = "zero_padded_hello",
                decoyRepeats = 2,
                sniCaseObfuscation = "random_mixed",
                greaseObfuscation = true,
                engineMode = "vpn_safe_kotlin",
                bypassVpnTun = true
            )
        ),
        SavedProfile(
            id = "preset_oob_sni_split",
            name = "CDN OOB Urgent + SNI Split",
            config = SpoofConfig(
                listenPort = 40443,
                connectIp = "104.18.4.130",
                connectPort = 443,
                fakeSni = "www.hcaptcha.com",
                method = "oob",
                fragmentStrategy = "sni_split",
                fragmentDelayMs = 8,
                engineMode = "vpn_safe_kotlin",
                bypassVpnTun = true
            )
        )
    )

    fun serializeConfigJson(c: SpoofConfig): JSONObject = JSONObject()
        .put("listenPort", c.listenPort)
        .put("connectIp", c.connectIp)
        .put("connectPort", c.connectPort)
        .put("fakeSni", c.fakeSni)
        .put("method", c.method)
        .put("fragmentStrategy", c.fragmentStrategy)
        .put("fragmentDelayMs", c.fragmentDelayMs)
        .put("handshakeTimeoutMs", c.handshakeTimeoutMs)
        .put("connectTimeoutMs", c.connectTimeoutMs)
        .put("logLevel", c.logLevel)
        .put("engineMode", c.engineMode)
        .put("bypassVpnTun", c.bypassVpnTun)
        .put("decoyTtl", c.decoyTtl)
        .put("chunkSize", c.chunkSize)
        .put("fragmentCount", c.fragmentCount)
        .put("tcpNoDelay", c.tcpNoDelay)
        .put("byteRangeSpec", c.byteRangeSpec)
        .put("delayRangeSpec", c.delayRangeSpec)
        .put("sniOffsetShift", c.sniOffsetShift)
        .put("sniCaseObfuscation", c.sniCaseObfuscation)
        .put("tlsPaddingSize", c.tlsPaddingSize)
        .put("greaseObfuscation", c.greaseObfuscation)
        .put("tlsRecordVersionCap", c.tlsRecordVersionCap)
        .put("decoyPayloadMode", c.decoyPayloadMode)
        .put("decoyRepeats", c.decoyRepeats)

    fun parseConfigJson(obj: JSONObject): SpoofConfig = SpoofConfig(
        listenPort = obj.optInt("listenPort", 40443),
        connectIp = obj.optString("connectIp", "104.18.4.130"),
        connectPort = obj.optInt("connectPort", 443),
        fakeSni = obj.optString("fakeSni", "speed.cloudflare.com"),
        // Unknown ids (e.g. the removed "sni_rewrite", or strategies like "record_split" that older
        // benchmark versions stored) fall back to working defaults instead of silently misbehaving.
        method = obj.optString("method", "combined").takeIf { it in SpoofConfig.METHODS } ?: "combined",
        fragmentStrategy = obj.optString("fragmentStrategy", "sni_split")
            .takeIf { it in SpoofConfig.FRAGMENT_STRATEGIES } ?: "sni_split",
        fragmentDelayMs = obj.optInt("fragmentDelayMs", 10),
        handshakeTimeoutMs = obj.optInt("handshakeTimeoutMs", 2500),
        connectTimeoutMs = obj.optInt("connectTimeoutMs", 5000),
        logLevel = obj.optString("logLevel", "info"),
        engineMode = obj.optString("engineMode", "vpn_safe_kotlin"),
        bypassVpnTun = obj.optBoolean("bypassVpnTun", true),
        decoyTtl = obj.optInt("decoyTtl", 4),
        chunkSize = obj.optInt("chunkSize", 24),
        fragmentCount = obj.optInt("fragmentCount", 4),
        tcpNoDelay = obj.optBoolean("tcpNoDelay", true),
        byteRangeSpec = obj.optString("byteRangeSpec", "1-5, 8-24, 32-64"),
        delayRangeSpec = obj.optString("delayRangeSpec", "5-15"),
        sniOffsetShift = obj.optInt("sniOffsetShift", 2),
        sniCaseObfuscation = obj.optString("sniCaseObfuscation", "none"),
        tlsPaddingSize = obj.optInt("tlsPaddingSize", 0),
        greaseObfuscation = obj.optBoolean("greaseObfuscation", false),
        tlsRecordVersionCap = obj.optString("tlsRecordVersionCap", "keep"),
        decoyPayloadMode = obj.optString("decoyPayloadMode", "fake_client_hello"),
        decoyRepeats = obj.optInt("decoyRepeats", 1)
    )
}
