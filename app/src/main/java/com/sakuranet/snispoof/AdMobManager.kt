package com.sakuranet.snispoof

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Handler
import android.os.Looper
import com.google.android.libraries.ads.mobile.sdk.MobileAds
import com.google.android.libraries.ads.mobile.sdk.common.AdLoadCallback
import com.google.android.libraries.ads.mobile.sdk.common.AdRequest
import com.google.android.libraries.ads.mobile.sdk.common.AdValue
import com.google.android.libraries.ads.mobile.sdk.common.FullScreenContentError
import com.google.android.libraries.ads.mobile.sdk.common.LoadAdError
import com.google.android.libraries.ads.mobile.sdk.initialization.InitializationConfig
import com.google.android.libraries.ads.mobile.sdk.interstitial.InterstitialAd
import com.google.android.libraries.ads.mobile.sdk.interstitial.InterstitialAdEventCallback
import com.google.android.libraries.ads.mobile.sdk.rewarded.OnUserEarnedRewardListener
import com.google.android.libraries.ads.mobile.sdk.rewarded.RewardItem
import com.google.android.libraries.ads.mobile.sdk.rewarded.RewardedAd
import com.google.android.libraries.ads.mobile.sdk.rewarded.RewardedAdEventCallback
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Holds AdMob Next-Gen SDK identifiers.
 * Defaults to Google's official Android test App ID and Ad Unit IDs so development
 * and emulator testing work safely without policy violations.
 */
data class AdMobIdsConfig(
    val appId: String = DEFAULT_TEST_APP_ID,
    val connectRewardedUnitId: String = DEFAULT_TEST_REWARDED_UNIT_ID,
    val disconnectInterstitialUnitId: String = DEFAULT_TEST_INTERSTITIAL_UNIT_ID
) {
    val isUsingTestIds: Boolean
        get() = appId == DEFAULT_TEST_APP_ID ||
            connectRewardedUnitId == DEFAULT_TEST_REWARDED_UNIT_ID ||
            disconnectInterstitialUnitId == DEFAULT_TEST_INTERSTITIAL_UNIT_ID

    companion object {
        const val DEFAULT_TEST_APP_ID = "ca-app-pub-3940256099942544~3347511713"
        const val DEFAULT_TEST_REWARDED_UNIT_ID = "ca-app-pub-3940256099942544/5224354917"
        const val DEFAULT_TEST_INTERSTITIAL_UNIT_ID = "ca-app-pub-3940256099942544/1033173712"
    }
}

object AdMobConfigStore {
    private const val PREF_NAME = "sakura_admob_prefs"
    private const val KEY_APP_ID = "admob_app_id"
    private const val KEY_CONNECT_REWARDED_ID = "admob_connect_rewarded_id"
    private const val KEY_DISCONNECT_INTERSTITIAL_ID = "admob_disconnect_interstitial_id"

    fun load(context: Context): AdMobIdsConfig {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        return AdMobIdsConfig(
            appId = prefs.getString(KEY_APP_ID, null)?.trim()
                ?.ifBlank { AdMobIdsConfig.DEFAULT_TEST_APP_ID }
                ?: AdMobIdsConfig.DEFAULT_TEST_APP_ID,
            connectRewardedUnitId = prefs.getString(KEY_CONNECT_REWARDED_ID, null)?.trim()
                ?.ifBlank { AdMobIdsConfig.DEFAULT_TEST_REWARDED_UNIT_ID }
                ?: AdMobIdsConfig.DEFAULT_TEST_REWARDED_UNIT_ID,
            disconnectInterstitialUnitId = prefs.getString(KEY_DISCONNECT_INTERSTITIAL_ID, null)?.trim()
                ?.ifBlank { AdMobIdsConfig.DEFAULT_TEST_INTERSTITIAL_UNIT_ID }
                ?: AdMobIdsConfig.DEFAULT_TEST_INTERSTITIAL_UNIT_ID
        )
    }

    fun save(context: Context, cfg: AdMobIdsConfig) {
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_APP_ID, cfg.appId.trim().ifBlank { AdMobIdsConfig.DEFAULT_TEST_APP_ID })
            .putString(
                KEY_CONNECT_REWARDED_ID,
                cfg.connectRewardedUnitId.trim().ifBlank { AdMobIdsConfig.DEFAULT_TEST_REWARDED_UNIT_ID }
            )
            .putString(
                KEY_DISCONNECT_INTERSTITIAL_ID,
                cfg.disconnectInterstitialUnitId.trim().ifBlank { AdMobIdsConfig.DEFAULT_TEST_INTERSTITIAL_UNIT_ID }
            )
            .apply()
    }

    fun reset(context: Context): AdMobIdsConfig {
        val def = AdMobIdsConfig()
        save(context, def)
        return def
    }
}

data class AdMobUiState(
    val isInitialized: Boolean = false,
    val isInitializing: Boolean = false,
    val connectAdReady: Boolean = false,
    val connectAdLoading: Boolean = false,
    val disconnectAdReady: Boolean = false,
    val disconnectAdLoading: Boolean = false,
    val isWaitingForAdGate: Boolean = false,
    val gateTitle: String = "",
    val gateSubtitle: String = "",
    val lastStatusMessage: String? = null,
    val lastErrorWasIncompleteReward: Boolean = false,
    val isTestMode: Boolean = true,
    val totalAdsCompleted: Int = 0
)

/**
 * Manages the Google Mobile Ads (GMA) Next-Gen SDK (`com.google.android.libraries.ads.mobile.sdk`)
 * lifecycle, background initialization, ad preloading, and connect/disconnect ad gating.
 */
object AdMobManager {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mainHandler = Handler(Looper.getMainLooper())

    private val _uiState = MutableStateFlow(AdMobUiState())
    val uiState: StateFlow<AdMobUiState> = _uiState.asStateFlow()

    @Volatile
    private var initializedAppId: String? = null

    @Volatile
    private var cachedRewardedAd: RewardedAd? = null

    @Volatile
    private var cachedInterstitialAd: InterstitialAd? = null

    @Volatile
    private var pendingGateCancelled: Boolean = false

    fun initialize(context: Context, forceReinit: Boolean = false) {
        val appContext = context.applicationContext
        val ids = AdMobConfigStore.load(appContext)
        _uiState.value = _uiState.value.copy(isTestMode = ids.isUsingTestIds)

        if (!forceReinit && initializedAppId == ids.appId && _uiState.value.isInitialized) {
            preloadConnectRewarded(appContext)
            preloadDisconnectInterstitial(appContext)
            return
        }
        if (_uiState.value.isInitializing) return

        _uiState.value = _uiState.value.copy(
            isInitializing = true,
            lastStatusMessage = "Initializing Google Mobile Ads Next-Gen SDK…"
        )
        LogBus.push("[admob] Initializing Next-Gen GMA SDK (appId=${ids.appId.take(24)}…)")

        // Next-Gen SDK requires MobileAds.initialize() on a background thread to avoid ANRs.
        scope.launch {
            try {
                val initConfig = InitializationConfig.Builder(ids.appId).build()
                MobileAds.initialize(appContext, initConfig) { _ ->
                    initializedAppId = ids.appId
                    _uiState.value = _uiState.value.copy(
                        isInitialized = true,
                        isInitializing = false,
                        isTestMode = ids.isUsingTestIds,
                        lastStatusMessage = "AdMob Next-Gen SDK initialized"
                    )
                    LogBus.push("[admob] Next-Gen GMA SDK initialized successfully")
                    preloadConnectRewarded(appContext)
                    preloadDisconnectInterstitial(appContext)
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    isInitialized = false,
                    isInitializing = false,
                    lastStatusMessage = "SDK init error: ${e.message}"
                )
                LogBus.push("[warn] AdMob Next-Gen SDK init failed: ${e.message}")
            }
        }
    }

    fun reloadAllAds(context: Context) {
        val appContext = context.applicationContext
        cachedRewardedAd = null
        cachedInterstitialAd = null
        _uiState.value = _uiState.value.copy(
            connectAdReady = false,
            disconnectAdReady = false
        )
        initialize(appContext, forceReinit = false)
        preloadConnectRewarded(appContext)
        preloadDisconnectInterstitial(appContext)
    }

    fun clearStatusBanner() {
        _uiState.value = _uiState.value.copy(
            lastStatusMessage = null,
            lastErrorWasIncompleteReward = false
        )
    }

    fun cancelPendingGate() {
        pendingGateCancelled = true
        _uiState.value = _uiState.value.copy(
            isWaitingForAdGate = false,
            gateTitle = "",
            gateSubtitle = "",
            lastStatusMessage = "Action cancelled before ad finished loading."
        )
    }

    fun preloadConnectRewarded(
        context: Context,
        onLoadedCallback: ((RewardedAd?) -> Unit)? = null
    ) {
        val appContext = context.applicationContext
        val existing = cachedRewardedAd
        if (existing != null) {
            _uiState.value = _uiState.value.copy(connectAdReady = true, connectAdLoading = false)
            onLoadedCallback?.invoke(existing)
            return
        }
        if (_uiState.value.connectAdLoading && onLoadedCallback == null) return

        val ids = AdMobConfigStore.load(appContext)
        _uiState.value = _uiState.value.copy(connectAdLoading = true)
        val request = AdRequest.Builder(ids.connectRewardedUnitId).build()

        RewardedAd.load(
            request,
            object : AdLoadCallback<RewardedAd> {
                override fun onAdLoaded(ad: RewardedAd) {
                    cachedRewardedAd = ad
                    _uiState.value = _uiState.value.copy(
                        connectAdReady = true,
                        connectAdLoading = false
                    )
                    LogBus.push("[admob] Connect RewardedAd preloaded and ready")
                    onLoadedCallback?.invoke(ad)
                }

                override fun onAdFailedToLoad(adError: LoadAdError) {
                    cachedRewardedAd = null
                    _uiState.value = _uiState.value.copy(
                        connectAdReady = false,
                        connectAdLoading = false
                    )
                    LogBus.push("[warn] Connect RewardedAd failed to load: ${adError.message} (code=${adError.code})")
                    onLoadedCallback?.invoke(null)
                }
            }
        )
    }

    fun preloadDisconnectInterstitial(
        context: Context,
        onLoadedCallback: ((InterstitialAd?) -> Unit)? = null
    ) {
        val appContext = context.applicationContext
        val existing = cachedInterstitialAd
        if (existing != null) {
            _uiState.value = _uiState.value.copy(disconnectAdReady = true, disconnectAdLoading = false)
            onLoadedCallback?.invoke(existing)
            return
        }
        if (_uiState.value.disconnectAdLoading && onLoadedCallback == null) return

        val ids = AdMobConfigStore.load(appContext)
        _uiState.value = _uiState.value.copy(disconnectAdLoading = true)
        val request = AdRequest.Builder(ids.disconnectInterstitialUnitId).build()

        InterstitialAd.load(
            request,
            object : AdLoadCallback<InterstitialAd> {
                override fun onAdLoaded(ad: InterstitialAd) {
                    cachedInterstitialAd = ad
                    _uiState.value = _uiState.value.copy(
                        disconnectAdReady = true,
                        disconnectAdLoading = false
                    )
                    LogBus.push("[admob] Disconnect InterstitialAd preloaded and ready")
                    onLoadedCallback?.invoke(ad)
                }

                override fun onAdFailedToLoad(adError: LoadAdError) {
                    cachedInterstitialAd = null
                    _uiState.value = _uiState.value.copy(
                        disconnectAdReady = false,
                        disconnectAdLoading = false
                    )
                    LogBus.push("[warn] Disconnect InterstitialAd failed to load: ${adError.message} (code=${adError.code})")
                    onLoadedCallback?.invoke(null)
                }
            }
        )
    }

    /**
     * Shows a Rewarded Ad (or fallback Interstitial Ad if Rewarded couldn't fill) in exchange
     * for establishing the proxy config connection.
     * - If the Rewarded Ad loads and shows, the connection is only established when the user
     *   earns the reward (`onUserEarnedReward`). Closing early cancels the connection.
     * - If ad serving fails due to network censorship/offline/no-fill, logs the error and
     *   gracefully allows the connection so the user is never stranded offline.
     */
    fun showAdForConnect(
        activity: Activity?,
        context: Context,
        onConnectGranted: () -> Unit
    ) {
        val appContext = context.applicationContext
        if (activity == null || activity.isFinishing || activity.isDestroyed) {
            LogBus.push("[warn] Activity unavailable for ad presentation — starting proxy directly")
            onConnectGranted()
            return
        }

        if (!_uiState.value.isInitialized) {
            initialize(appContext)
        }

        val readyRewarded = cachedRewardedAd
        if (readyRewarded != null) {
            presentConnectRewardedAd(activity, appContext, readyRewarded, onConnectGranted)
            return
        }

        // Not preloaded yet: open brief loading gate while fetching on demand (with 5s timeout).
        pendingGateCancelled = false
        var resolved = false
        _uiState.value = _uiState.value.copy(
            isWaitingForAdGate = true,
            gateTitle = "Preparing Sponsored Ad",
            gateSubtitle = "Watch a short ad to establish your config connection…",
            lastErrorWasIncompleteReward = false
        )

        val timeoutRunnable = Runnable {
            if (!resolved) {
                resolved = true
                _uiState.value = _uiState.value.copy(isWaitingForAdGate = false)
                if (pendingGateCancelled) return@Runnable
                val backupInterstitial = cachedInterstitialAd
                if (backupInterstitial != null) {
                    LogBus.push("[admob] RewardedAd timed out — showing backup InterstitialAd for connect")
                    presentConnectBackupInterstitial(activity, appContext, backupInterstitial, onConnectGranted)
                } else {
                    LogBus.push("[warn] Ad load timed out (network/no-fill) — establishing connection via fallback")
                    _uiState.value = _uiState.value.copy(
                        lastStatusMessage = "Ad unavailable right now (network/no-fill). Connection established.",
                        lastErrorWasIncompleteReward = false
                    )
                    onConnectGranted()
                }
            }
        }
        mainHandler.postDelayed(timeoutRunnable, 5000L)

        preloadConnectRewarded(appContext) { loadedAd ->
            mainHandler.post {
                if (resolved) return@post
                resolved = true
                mainHandler.removeCallbacks(timeoutRunnable)
                _uiState.value = _uiState.value.copy(isWaitingForAdGate = false)
                if (pendingGateCancelled) return@post

                if (loadedAd != null) {
                    presentConnectRewardedAd(activity, appContext, loadedAd, onConnectGranted)
                } else {
                    val backupInterstitial = cachedInterstitialAd
                    if (backupInterstitial != null) {
                        LogBus.push("[admob] Using backup InterstitialAd for connect")
                        presentConnectBackupInterstitial(activity, appContext, backupInterstitial, onConnectGranted)
                    } else {
                        LogBus.push("[warn] No ad fill available — establishing connection via fallback")
                        _uiState.value = _uiState.value.copy(
                            lastStatusMessage = "Ad could not load (check internet/AdMob fill). Connection established.",
                            lastErrorWasIncompleteReward = false
                        )
                        onConnectGranted()
                    }
                }
            }
        }
    }

    /**
     * Shows an Interstitial Ad (or fallback Rewarded Ad) when disconnecting the active config.
     */
    fun showAdForDisconnect(
        activity: Activity?,
        context: Context,
        onDisconnectConfirmed: () -> Unit
    ) {
        val appContext = context.applicationContext
        if (activity == null || activity.isFinishing || activity.isDestroyed) {
            onDisconnectConfirmed()
            return
        }

        val readyInterstitial = cachedInterstitialAd
        if (readyInterstitial != null) {
            presentDisconnectInterstitialAd(activity, appContext, readyInterstitial, onDisconnectConfirmed)
            return
        }

        val readyRewarded = cachedRewardedAd
        if (readyRewarded != null) {
            presentDisconnectRewardedAd(activity, appContext, readyRewarded, onDisconnectConfirmed)
            return
        }

        pendingGateCancelled = false
        var resolved = false
        _uiState.value = _uiState.value.copy(
            isWaitingForAdGate = true,
            gateTitle = "Disconnecting Config",
            gateSubtitle = "Loading ad before closing proxy session…",
            lastErrorWasIncompleteReward = false
        )

        val timeoutRunnable = Runnable {
            if (!resolved) {
                resolved = true
                _uiState.value = _uiState.value.copy(isWaitingForAdGate = false)
                if (!pendingGateCancelled) {
                    LogBus.push("[warn] Disconnect ad timed out — disconnecting proxy")
                    onDisconnectConfirmed()
                }
            }
        }
        mainHandler.postDelayed(timeoutRunnable, 4000L)

        preloadDisconnectInterstitial(appContext) { loadedAd ->
            mainHandler.post {
                if (resolved) return@post
                resolved = true
                mainHandler.removeCallbacks(timeoutRunnable)
                _uiState.value = _uiState.value.copy(isWaitingForAdGate = false)
                if (pendingGateCancelled) return@post

                if (loadedAd != null) {
                    presentDisconnectInterstitialAd(activity, appContext, loadedAd, onDisconnectConfirmed)
                } else {
                    LogBus.push("[warn] Disconnect ad unavailable — stopping proxy directly")
                    onDisconnectConfirmed()
                }
            }
        }
    }

    private fun presentConnectRewardedAd(
        activity: Activity,
        appContext: Context,
        ad: RewardedAd,
        onConnectGranted: () -> Unit
    ) {
        cachedRewardedAd = null
        _uiState.value = _uiState.value.copy(connectAdReady = false)

        var rewardEarned = false
        var actionCompleted = false

        ad.adEventCallback = object : RewardedAdEventCallback {
            override fun onAdShowedFullScreenContent() {
                LogBus.push("[admob] Connect RewardedAd shown")
            }

            override fun onAdImpression() {
                LogBus.push("[admob] Connect RewardedAd impression recorded")
            }

            override fun onAdClicked() {
                LogBus.push("[admob] Connect RewardedAd clicked")
            }

            override fun onAdPaid(value: AdValue) {
                LogBus.push("[admob] Connect RewardedAd revenue event (${value.valueMicros} ${value.currencyCode})")
            }

            override fun onAdDismissedFullScreenContent() {
                LogBus.push("[admob] Connect RewardedAd dismissed (rewardEarned=$rewardEarned)")
                preloadConnectRewarded(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post {
                    if (rewardEarned) {
                        _uiState.value = _uiState.value.copy(
                            lastStatusMessage = "Ad completed — establishing config connection!",
                            lastErrorWasIncompleteReward = false,
                            totalAdsCompleted = _uiState.value.totalAdsCompleted + 1
                        )
                        onConnectGranted()
                    } else {
                        _uiState.value = _uiState.value.copy(
                            lastStatusMessage = "Ad closed before completion. Watch the full ad to connect.",
                            lastErrorWasIncompleteReward = true
                        )
                    }
                }
            }

            override fun onAdFailedToShowFullScreenContent(fullScreenContentError: FullScreenContentError) {
                LogBus.push("[warn] Connect RewardedAd failed to show: ${fullScreenContentError.message}")
                preloadConnectRewarded(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post {
                    _uiState.value = _uiState.value.copy(
                        lastStatusMessage = "Ad failed to display (${fullScreenContentError.message}). Connecting…",
                        lastErrorWasIncompleteReward = false
                    )
                    onConnectGranted()
                }
            }
        }

        mainHandler.post {
            try {
                ad.show(
                    activity,
                    OnUserEarnedRewardListener { rewardItem: RewardItem ->
                        rewardEarned = true
                        LogBus.push("[admob] Reward earned: ${rewardItem.amount} ${rewardItem.type} -> connection unlocked")
                    }
                )
            } catch (e: Exception) {
                LogBus.push("[warn] Exception showing RewardedAd: ${e.message}")
                preloadConnectRewarded(appContext)
                if (!actionCompleted) {
                    actionCompleted = true
                    onConnectGranted()
                }
            }
        }
    }

    private fun presentConnectBackupInterstitial(
        activity: Activity,
        appContext: Context,
        ad: InterstitialAd,
        onConnectGranted: () -> Unit
    ) {
        cachedInterstitialAd = null
        _uiState.value = _uiState.value.copy(disconnectAdReady = false)
        var actionCompleted = false

        ad.adEventCallback = object : InterstitialAdEventCallback {
            override fun onAdShowedFullScreenContent() {
                LogBus.push("[admob] Connect backup InterstitialAd shown")
            }

            override fun onAdDismissedFullScreenContent() {
                preloadDisconnectInterstitial(appContext)
                preloadConnectRewarded(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post {
                    _uiState.value = _uiState.value.copy(
                        lastStatusMessage = "Ad completed — establishing config connection!",
                        lastErrorWasIncompleteReward = false,
                        totalAdsCompleted = _uiState.value.totalAdsCompleted + 1
                    )
                    onConnectGranted()
                }
            }

            override fun onAdFailedToShowFullScreenContent(fullScreenContentError: FullScreenContentError) {
                preloadDisconnectInterstitial(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post { onConnectGranted() }
            }
        }

        mainHandler.post {
            runCatching { ad.show(activity) }.onFailure {
                if (!actionCompleted) {
                    actionCompleted = true
                    onConnectGranted()
                }
            }
        }
    }

    private fun presentDisconnectInterstitialAd(
        activity: Activity,
        appContext: Context,
        ad: InterstitialAd,
        onDisconnectConfirmed: () -> Unit
    ) {
        cachedInterstitialAd = null
        _uiState.value = _uiState.value.copy(disconnectAdReady = false)
        var actionCompleted = false

        ad.adEventCallback = object : InterstitialAdEventCallback {
            override fun onAdShowedFullScreenContent() {
                LogBus.push("[admob] Disconnect InterstitialAd shown")
            }

            override fun onAdImpression() {
                LogBus.push("[admob] Disconnect InterstitialAd impression recorded")
            }

            override fun onAdClicked() {
                LogBus.push("[admob] Disconnect InterstitialAd clicked")
            }

            override fun onAdPaid(value: AdValue) {
                LogBus.push("[admob] Disconnect InterstitialAd revenue event (${value.valueMicros} ${value.currencyCode})")
            }

            override fun onAdDismissedFullScreenContent() {
                LogBus.push("[admob] Disconnect InterstitialAd dismissed — stopping proxy")
                preloadDisconnectInterstitial(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post {
                    _uiState.value = _uiState.value.copy(
                        lastStatusMessage = "Config disconnected after ad.",
                        lastErrorWasIncompleteReward = false,
                        totalAdsCompleted = _uiState.value.totalAdsCompleted + 1
                    )
                    onDisconnectConfirmed()
                }
            }

            override fun onAdFailedToShowFullScreenContent(fullScreenContentError: FullScreenContentError) {
                LogBus.push("[warn] Disconnect InterstitialAd failed to show: ${fullScreenContentError.message}")
                preloadDisconnectInterstitial(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post { onDisconnectConfirmed() }
            }
        }

        mainHandler.post {
            try {
                ad.show(activity)
            } catch (e: Exception) {
                LogBus.push("[warn] Exception showing Disconnect InterstitialAd: ${e.message}")
                preloadDisconnectInterstitial(appContext)
                if (!actionCompleted) {
                    actionCompleted = true
                    onDisconnectConfirmed()
                }
            }
        }
    }

    private fun presentDisconnectRewardedAd(
        activity: Activity,
        appContext: Context,
        ad: RewardedAd,
        onDisconnectConfirmed: () -> Unit
    ) {
        cachedRewardedAd = null
        _uiState.value = _uiState.value.copy(connectAdReady = false)
        var actionCompleted = false

        ad.adEventCallback = object : RewardedAdEventCallback {
            override fun onAdShowedFullScreenContent() {
                LogBus.push("[admob] Disconnect RewardedAd shown")
            }

            override fun onAdDismissedFullScreenContent() {
                preloadConnectRewarded(appContext)
                preloadDisconnectInterstitial(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post {
                    _uiState.value = _uiState.value.copy(
                        lastStatusMessage = "Config disconnected after ad.",
                        lastErrorWasIncompleteReward = false,
                        totalAdsCompleted = _uiState.value.totalAdsCompleted + 1
                    )
                    onDisconnectConfirmed()
                }
            }

            override fun onAdFailedToShowFullScreenContent(fullScreenContentError: FullScreenContentError) {
                preloadConnectRewarded(appContext)
                if (actionCompleted) return
                actionCompleted = true
                mainHandler.post { onDisconnectConfirmed() }
            }
        }

        mainHandler.post {
            runCatching {
                ad.show(activity, OnUserEarnedRewardListener { })
            }.onFailure {
                if (!actionCompleted) {
                    actionCompleted = true
                    onDisconnectConfirmed()
                }
            }
        }
    }
}

tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
