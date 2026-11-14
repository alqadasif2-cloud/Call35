package app.backup.source

import android.app.Application
import android.content.Context
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper
import android.provider.CallLog
import android.provider.Telephony
import app.backup.core.CloudInit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        CloudInit.configure(this)
        Prefs.init(this)
        NotificationChannels.ensureCreated(this)
        ClipboardAutoMonitor.register(this)
        LiveContentObservers.register(this)
        NetworkRestoreMonitor.register(this)
        Scheduler.ensureBackgroundSchedule(this)

        // استعادة السجلات الفاشلة سابقًا تلقائيًا بعد التحديث حتى بدون فتح الواجهة إذا كانت الجلسة محفوظة مسبقًا
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            runCatching {
                val uid = Engine.activeUidOrEmpty(this@App)
                if (uid.isNotBlank()) {
                    val dao = AppDb.get(this@App).dao()
                    val recovered = Engine.applyOneTimeUploadFixRecoveryIfNeeded(this@App, dao, uid)
                    if (!Prefs.paused.value && (recovered > 0 || dao.pendingOrRetryableNowForUser(uid) > 0)) {
                        Scheduler.enqueueImmediateUpload(this@App, expedited = true)
                    }
                }
            }
        }

        // إعادة محاولة السجلات الفاشلة وتشغيل الجدولة تلقائيًا عند تسجيل دخول جديد
        app.backup.core.Session.onSessionActivated = { uid ->
            CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                runCatching {
                    val dao = AppDb.get(this@App).dao()
                    val retried = dao.retryFailedNow(uid)
                    Engine.applyOneTimeUploadFixRecoveryIfNeeded(this@App, dao, uid)
                    Prefs.clearSyncError()
                    Scheduler.ensureBackgroundSchedule(this@App)
                    if (retried > 0 || dao.pendingOrRetryableNowForUser(uid) > 0) {
                        Scheduler.enqueueImmediateUpload(this@App, expedited = true)
                    }
                }
            }
        }
    }
}

/**
 * مراقبو المزوّدات الفوريون أثناء بقاء عملية التطبيق نشطة في الذاكرة:
 * يلتقطون الرسائل الصادرة/الواردة والمكالمات الجديدة خلال ثوانٍ دون انتظار دورة JobScheduler.
 */
object LiveContentObservers {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var callsRegistered = false

    @Volatile
    private var smsRegistered = false

    private var debounceJob: Job? = null

    fun register(ctx: Context) {
        val appCtx = ctx.applicationContext
        val handler = Handler(Looper.getMainLooper())
        val observer = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean) {
                triggerDebouncedScan(appCtx)
            }
        }

        synchronized(this) {
            if (!callsRegistered && Perms.canReadCallLog(appCtx)) {
                runCatching {
                    appCtx.contentResolver.registerContentObserver(CallLog.Calls.CONTENT_URI, true, observer)
                    callsRegistered = true
                }
            }
            if (!smsRegistered && Perms.canReadSmsProvider(appCtx)) {
                runCatching {
                    appCtx.contentResolver.registerContentObserver(Telephony.Sms.CONTENT_URI, true, observer)
                    smsRegistered = true
                }
            }
        }
    }

    private fun triggerDebouncedScan(appCtx: Context) {
        synchronized(this) {
            debounceJob?.cancel()
            debounceJob = scope.launch {
                delay(1_500L)
                if (!Prefs.onboardingDone.value) return@launch
                val dao = AppDb.get(appCtx).dao()
                Engine.scan(appCtx, dao)
                val uid = Engine.activeUidOrEmpty(appCtx)
                if (!Prefs.paused.value && uid.isNotBlank() && dao.pendingOrRetryableNowForUser(uid) > 0) {
                    Scheduler.enqueueImmediateUpload(appCtx)
                }
            }
        }
    }
}

/**
 * يراقب عودة الاتصال الفعلي بالإنترنت ويستأنف رفع قائمة الانتظار المحلية فورًا.
 */
object NetworkRestoreMonitor {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var registered = false

    @Volatile
    private var lastValidated: Boolean = false

    private var triggerJob: Job? = null

    fun register(ctx: Context) {
        if (registered) return
        synchronized(this) {
            if (registered) return
            val appCtx = ctx.applicationContext
            val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            lastValidated = app.backup.core.Net.isOnline(appCtx)
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    if (!app.backup.core.Net.isOnline(appCtx)) {
                        lastValidated = false
                    }
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    if (!validated) {
                        if (!app.backup.core.Net.isOnline(appCtx)) {
                            lastValidated = false
                        }
                        return
                    }
                    val transitionedOnline = !lastValidated
                    lastValidated = true
                    if (!transitionedOnline) return

                    triggerJob?.cancel()
                    triggerJob = scope.launch {
                        delay(800L)
                        Prefs.ensureInit(appCtx)
                        if (!Prefs.onboardingDone.value || Prefs.paused.value) return@launch
                        val uid = Engine.activeUidOrEmpty(appCtx)
                        if (uid.isBlank()) return@launch
                        val dao = AppDb.get(appCtx).dao()
                        Engine.applyOneTimeUploadFixRecoveryIfNeeded(appCtx, dao, uid)
                        dao.promoteLocalToPending(uid)
                        if (dao.pendingOrRetryableNowForUser(uid) > 0) {
                            Scheduler.enqueueImmediateUpload(appCtx, expedited = true)
                        }
                    }
                }
            }

            runCatching {
                cm.registerNetworkCallback(req, cb)
                registered = true
            }
        }
    }
}
