package app.backup.core

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseNetworkException
import com.google.firebase.FirebaseOptions
import com.google.firebase.FirebaseTooManyRequestsException
import com.google.firebase.auth.EmailAuthProvider
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException
import com.google.firebase.auth.FirebaseAuthInvalidUserException
import com.google.firebase.auth.FirebaseAuthRecentLoginRequiredException
import com.google.firebase.auth.FirebaseAuthUserCollisionException
import com.google.firebase.auth.FirebaseAuthWeakPasswordException
import com.google.firebase.firestore.AggregateSource
import com.google.firebase.firestore.DocumentSnapshot
import com.google.firebase.firestore.FieldValue
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.FirebaseFirestoreException
import com.google.firebase.firestore.FirebaseFirestoreSettings
import com.google.firebase.firestore.MemoryCacheSettings
import com.google.firebase.firestore.Query
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext

object CloudInit {
    internal val DEFAULT_PROJECT_ID: String = BuildConfig.FIREBASE_PROJECT_ID
    private val DEFAULT_APP_ID: String = BuildConfig.FIREBASE_APP_ID
    private val DEFAULT_API_KEY: String = BuildConfig.FIREBASE_API_KEY
    private val DEFAULT_SENDER_ID: String = BuildConfig.FIREBASE_SENDER_ID
    private val DEFAULT_STORAGE_BUCKET: String = BuildConfig.FIREBASE_STORAGE_BUCKET
    private const val CLOUD_FUNCTION_REGION = "us-central1"
    val PROVISIONED_DB_ID: String = BuildConfig.FIREBASE_DATABASE_ID

    @Volatile
    var databaseId: String = PROVISIONED_DB_ID

    fun projectCustomAuthEndpoint(): String {
        val projectId = runCatching { FirebaseApp.getInstance().options.projectId }
            .getOrNull()
            ?.trim()
            .orEmpty()
            .ifEmpty { DEFAULT_PROJECT_ID }
        return "https://$CLOUD_FUNCTION_REGION-$projectId.cloudfunctions.net/authUsername"
    }

    fun firestore(): FirebaseFirestore {
        val app = FirebaseApp.getInstance()
        val useNamedDb = app.options.projectId == DEFAULT_PROJECT_ID &&
            databaseId.isNotBlank() &&
            databaseId != "(default)"
        return if (useNamedDb) {
            FirebaseFirestore.getInstance(app, databaseId)
        } else {
            FirebaseFirestore.getInstance(app)
        }
    }

    /** نستخدم Room كمخزن محلي وحيد، لذا نعطّل كاش Firestore الدائم كي لا تُعلَّق الكتابات بصمت دون تأكيد الخادم. */
    fun configure(ctx: Context? = null) {
        runCatching {
            if (ctx != null && FirebaseApp.getApps(ctx).isEmpty()) {
                val opts = FirebaseOptions.Builder()
                    .setProjectId(DEFAULT_PROJECT_ID)
                    .setApplicationId(DEFAULT_APP_ID)
                    .setApiKey(DEFAULT_API_KEY)
                    .setGcmSenderId(DEFAULT_SENDER_ID)
                    .setStorageBucket(DEFAULT_STORAGE_BUCKET)
                    .build()
                FirebaseApp.initializeApp(ctx, opts)
            }
            firestore().firestoreSettings = FirebaseFirestoreSettings.Builder()
                .setLocalCacheSettings(MemoryCacheSettings.newBuilder().build())
                .build()
        }
    }
}

object AuthMessages {
    fun of(e: Throwable): String {
        val raw = e.message.orEmpty()
        return when {
            e is UsernameAuthException -> raw.ifBlank { "تعذّر إتمام المصادقة." }
            e is FirebaseAuthUserCollisionException -> "اسم المستخدم مستخدم بالفعل. اختر اسمًا آخر."
            e is FirebaseAuthInvalidCredentialsException || e is FirebaseAuthInvalidUserException ->
                "اسم المستخدم أو كلمة المرور غير صحيحة."
            e is FirebaseAuthWeakPasswordException -> "يجب أن تتكون كلمة المرور من 8 أحرف على الأقل."
            e is FirebaseTooManyRequestsException ->
                "تم إيقاف المحاولات مؤقتًا لكثرة المحاولات الخاطئة. يرجى الانتظار قليلًا ثم المحاولة مجددًا."
            e is FirebaseAuthRecentLoginRequiredException ->
                "يلزم تسجيل دخول حديث. سجّل الخروج ثم الدخول وأعد المحاولة."
            e is FirebaseNetworkException -> "لا يوجد اتصال بالإنترنت. تحقق من الشبكة وأعد المحاولة."
            e is FirebaseFirestoreException && e.code == FirebaseFirestoreException.Code.UNAVAILABLE ->
                "لا يوجد اتصال بالإنترنت حاليًا. تحقق من الشبكة وأعد المحاولة."
            e is FirebaseFirestoreException && e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ->
                "رفضت قواعد الأمان السحابية هذه العملية. تأكد من صلاحية الجلسة وأن البيانات تتبع لحسابك."
            e is FirebaseFirestoreException -> "تعذّرت العملية السحابية (${e.code.name})"
            raw.isNotBlank() && raw.any { it in '\u0600'..'\u06FF' } -> raw
            else -> "تعذّر إتمام العملية السحابية. تحقق من الاتصال وأعد المحاولة."
        }
    }
}

sealed interface AuthSessionState {
    data object Valid : AuthSessionState
    data object ExpiredNeedsRefresh : AuthSessionState
    data class Invalid(val reason: String, val requiresRelogin: Boolean) : AuthSessionState
}

data class PageResult(val items: List<EncRecord>, val cursor: DocumentSnapshot?, val exhausted: Boolean)

class CloudRuleException(
    val operation: String,
    val path: String,
    val codeName: String,
    val detail: String,
    cause: Throwable? = null,
) : IllegalStateException(
    "رفضت قواعد أمان Firebase العملية ($operation على المسار $path — $codeName)${if (detail.isNotBlank()) ": $detail" else ""}",
    cause,
)

class CloudRepo(
    private val db: FirebaseFirestore = CloudInit.firestore(),
    private val auth: FirebaseAuth = FirebaseAuth.getInstance(),
    private val explicitUid: String? = null,
) {
    private val uid: String
        get() = explicitUid
            ?: Session.uid
            ?: auth.currentUser?.uid
            ?: throw IllegalStateException("not signed in")

    fun isVaultCapability(): Boolean = isVaultCapabilityId(uid)

    /**
     * يضمن توافق حالة FirebaseAuth مع نوع الحساب:
     * - حسابات القدرة المشفّرة (`v_...`) تتطلب أن يكون `request.auth == null` في قواعد الأمان.
     * - ننفذ `signOut()` ثم نمنح مستمعي Firestore فرصة تفريغ الرمز المخزن مؤقتًا قبل تنفيذ أي عملية كتابة/قراءة.
     */
    private suspend fun ensureCapabilityAuthClean() {
        if (isVaultCapability() && auth.currentUser != null) {
            runCatching {
                withContext(Dispatchers.Main.immediate) {
                    auth.signOut()
                }
            }.onFailure {
                runCatching { auth.signOut() }
            }
            delay(60L)
        }
    }

    private fun isValidDeviceSnapshot(snap: DocumentSnapshot): Boolean {
        val data = snap.data ?: return false
        if (data.keys != DEVICE_KEYS) return false
        if (snap.getString("ownerId") != uid) return false
        val name = snap.getString("name") ?: return false
        if (name.isEmpty() || name.length > 100) return false
        val model = snap.getString("model") ?: return false
        if (model.isEmpty() || model.length > 100) return false
        val en = snap.get("enabled") as? List<*> ?: return false
        if (en.size > 3 || en.any { it?.toString() !in ALLOWED_TYPES }) return false
        val lastSync = (data["lastSyncAt"] as? Number)?.toLong() ?: return false
        if (lastSync < 0L) return false
        if (snap.getTimestamp("createdAt") == null) return false
        if (snap.getTimestamp("updatedAt") == null) return false
        return true
    }

    private fun isValidRecordSnapshot(snap: DocumentSnapshot, deviceId: String, rec: EncRecord): Boolean {
        val data = snap.data ?: return false
        if (data.keys != RECORD_KEYS) return false
        if (snap.getString("ownerId") != uid) return false
        if (snap.getString("deviceId") != deviceId) return false
        if (snap.getString("type") != rec.type) return false
        val ts = (data["ts"] as? Number)?.toLong() ?: return false
        if (ts != rec.ts) return false
        val v = (data["v"] as? Number)?.toLong() ?: return false
        if (v != 1L) return false
        val iv = snap.getString("iv") ?: return false
        if (iv.length !in 12..64) return false
        val cipher = snap.getString("data") ?: return false
        if (cipher.length !in 16..MAX_CIPHERTEXT_LEN) return false
        if (snap.getTimestamp("createdAt") == null) return false
        if (snap.getTimestamp("updatedAt") == null) return false
        return true
    }

    /**
     * يتحقق مسبقًا من صلاحية جلسة الحساب وحالة رمز المصادقة (Auth Token) قبل تنفيذ عمليات Firestore.
     * يُعيد Valid إذا كانت الجلسة نشطة وسارية، أو ExpiredNeedsRefresh لإعادة المحاولة بعد التحديث،
     * أو Invalid إذا كانت الجلسة ملغاة أو منتهية تمامًا وتتطلب إعادة تسجيل الدخول.
     */
    suspend fun validateSession(forceRefresh: Boolean = false): AuthSessionState {
        if (isVaultCapability()) {
            ensureCapabilityAuthClean()
            return AuthSessionState.Valid
        }
        val currentFbUser = auth.currentUser
            ?: return AuthSessionState.Invalid("لم يتم العثور على جلسة مصادقة نشطة في Firebase.", requiresRelogin = true)

        if (currentFbUser.uid != uid) {
            return AuthSessionState.Invalid(
                "معرّف الجلسة الحالية (${currentFbUser.uid}) لا يطابق معرّف الحساب المطلوب ($uid).",
                requiresRelogin = true,
            )
        }

        return try {
            val tokenRes = currentFbUser.getIdToken(forceRefresh).await()
            if (tokenRes?.token.isNullOrBlank()) {
                AuthSessionState.Invalid("رمز المصادقة فارغ أو تم سحبه.", requiresRelogin = true)
            } else {
                AuthSessionState.Valid
            }
        } catch (e: Exception) {
            when {
                e is FirebaseAuthInvalidUserException || e is FirebaseAuthRecentLoginRequiredException ->
                    AuthSessionState.Invalid("انتهت صلاحية جلسة المستخدم في Firebase. يلزم إعادة الدخول.", requiresRelogin = true)
                e is FirebaseNetworkException || e is java.io.IOException ->
                    AuthSessionState.ExpiredNeedsRefresh
                e is FirebaseFirestoreException && e.code == FirebaseFirestoreException.Code.UNAUTHENTICATED ->
                    AuthSessionState.Invalid("انتهت صلاحية رمز المصادقة.", requiresRelogin = true)
                else -> {
                    val msg = e.message.orEmpty().lowercase()
                    if (msg.contains("expired") || msg.contains("invalid-user-token") || msg.contains("revoked")) {
                        AuthSessionState.Invalid("انتهت صلاحية رمز المصادقة في Firebase.", requiresRelogin = true)
                    } else {
                        AuthSessionState.ExpiredNeedsRefresh
                    }
                }
            }
        }
    }

    private fun user() = db.collection("users").document(uid)
    private fun usernameDoc(usernameId: String) = db.collection("usernames").document(usernameId)
    private fun cryptoDoc() = user().collection("meta").document("crypto")
    private fun devices() = user().collection("devices")
    private fun records(deviceId: String) = devices().document(deviceId).collection("records")

    // ---------- تسجيل حساب سحابي ذري ومنع تكرار اسم المستخدم ----------
    suspend fun registerCapabilityAccount(norm: NormalizedUsername, pass: CharArray): ByteArray {
        ensureCapabilityAuthClean()
        val salt = Crypto.randomBytes(16)
        val key = withContext(Dispatchers.Default) { Crypto.deriveKey(pass, salt) }
        val box = Crypto.encrypt(key, CHECK_PLAIN, CHECK_AAD)

        val b = db.batch()
        b.set(
            usernameDoc(norm.usernameId),
            mapOf(
                "uid" to uid,
                "usernameLower" to norm.usernameLower,
                "createdAt" to FieldValue.serverTimestamp(),
            )
        )
        b.set(
            user(),
            mapOf(
                "uid" to uid,
                "username" to norm.username,
                "usernameLower" to norm.usernameLower,
                "usernameId" to norm.usernameId,
                "createdAt" to FieldValue.serverTimestamp(),
            )
        )
        b.set(
            cryptoDoc(),
            mapOf(
                "uid" to uid,
                "salt" to Crypto.b64(salt),
                "iter" to Crypto.ITERATIONS,
                "checkIv" to Crypto.b64(box.iv),
                "check" to Crypto.b64(box.data),
                "v" to 1,
                "createdAt" to FieldValue.serverTimestamp(),
            )
        )

        try {
            b.commit().await()
            return key
        } catch (e: FirebaseFirestoreException) {
            key.fill(0)
            if (
                e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                e.code == FirebaseFirestoreException.Code.ALREADY_EXISTS
            ) {
                throw UsernameAuthException("اسم المستخدم مستخدم بالفعل. اختر اسمًا آخر.")
            }
            throw e
        } catch (e: Exception) {
            key.fill(0)
            throw e
        }
    }

    /** يتحقق من وجود ملف الحساب السحابي على Firestore ويعيد اسم المستخدم المحفوظ أو null إذا لم يطابق. */
    suspend fun lookupCapabilityAccountUsername(): String? {
        ensureCapabilityAuthClean()
        val snap = user().get().await()
        if (!snap.exists()) return null
        return snap.getString("username")?.takeIf { it.length >= 3 }
    }

    // ---------- ملف الحساب واسم المستخدم ----------
    suspend fun getCurrentUsername(): String? {
        ensureCapabilityAuthClean()
        val snap = user().get().await()
        return if (snap.exists()) snap.getString("username") else auth.currentUser?.displayName
    }

    suspend fun ensureUserProfile(norm: NormalizedUsername, isNewRegistration: Boolean) {
        ensureCapabilityAuthClean()
        val existing = user().get().await()
        if (existing.exists()) return

        if (isNewRegistration) {
            try {
                usernameDoc(norm.usernameId).set(
                    mapOf(
                        "uid" to uid,
                        "usernameLower" to norm.usernameLower,
                        "createdAt" to FieldValue.serverTimestamp(),
                    )
                ).await()
            } catch (e: FirebaseFirestoreException) {
                if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED) {
                    runCatching { auth.currentUser?.delete()?.await() }
                    throw UsernameAuthException("اسم المستخدم مستخدم بالفعل. اختر اسمًا آخر.")
                }
                throw e
            }
        } else {
            runCatching {
                usernameDoc(norm.usernameId).set(
                    mapOf(
                        "uid" to uid,
                        "usernameLower" to norm.usernameLower,
                        "createdAt" to FieldValue.serverTimestamp(),
                    )
                ).await()
            }
        }

        user().set(
            mapOf(
                "uid" to uid,
                "username" to norm.username,
                "usernameLower" to norm.usernameLower,
                "usernameId" to norm.usernameId,
                "createdAt" to FieldValue.serverTimestamp(),
            )
        ).await()
    }

    // ---------- التشفير ----------
    suspend fun hasCrypto(): Boolean {
        ensureCapabilityAuthClean()
        return cryptoDoc().get().await().exists()
    }

    suspend fun createCrypto(pass: CharArray): ByteArray {
        ensureCapabilityAuthClean()
        val salt = Crypto.randomBytes(16)
        val key = withContext(Dispatchers.Default) { Crypto.deriveKey(pass, salt) }
        val box = Crypto.encrypt(key, CHECK_PLAIN, CHECK_AAD)
        cryptoDoc().set(
            mapOf(
                "uid" to uid,
                "salt" to Crypto.b64(salt),
                "iter" to Crypto.ITERATIONS,
                "checkIv" to Crypto.b64(box.iv),
                "check" to Crypto.b64(box.data),
                "v" to 1,
                "createdAt" to FieldValue.serverTimestamp(),
            )
        ).await()
        return key
    }

    /** يعيد المفتاح، أو null إذا كانت كلمة المرور خاطئة. */
    suspend fun unlock(pass: CharArray): ByteArray? {
        ensureCapabilityAuthClean()
        val d = cryptoDoc().get().await()
        if (!d.exists()) return null
        val salt = Crypto.unb64(d.getString("salt")!!)
        val iter = (d.getLong("iter") ?: Crypto.ITERATIONS.toLong()).toInt()
        val key = withContext(Dispatchers.Default) { Crypto.deriveKey(pass, salt, iter) }
        return try {
            val plain = Crypto.decrypt(
                key,
                Crypto.unb64(d.getString("checkIv")!!),
                Crypto.unb64(d.getString("check")!!),
                CHECK_AAD,
            )
            if (plain.contentEquals(CHECK_PLAIN)) key else {
                key.fill(0)
                null
            }
        } catch (_: Exception) {
            key.fill(0)
            null
        }
    }

    // ---------- الأجهزة ----------
    suspend fun registerDevice(id: String, name: String, model: String, enabled: List<String>) {
        require(VALID_ID_REGEX.matches(uid) && uid.length in 1..128) { "معرّف الحساب غير صالح." }
        require(VALID_ID_REGEX.matches(id) && id.length in 1..128) { "معرّف الجهاز غير صالح." }
        ensureCapabilityAuthClean()

        val safeName = name.trim().ifEmpty { "هاتف أندرويد" }.take(100)
        val safeModel = model.trim().ifEmpty { "Android" }.take(100)
        val safeEnabled = enabled.filter { it in ALLOWED_TYPES }.distinct().take(3)
        val devicePath = "users/$uid/devices/$id"
        val ref = devices().document(id)

        suspend fun writeCleanDeviceDoc(preservedLastSyncAt: Long) {
            ref.set(
                mapOf(
                    "ownerId" to uid,
                    "name" to safeName,
                    "model" to safeModel,
                    "enabled" to safeEnabled,
                    "lastSyncAt" to preservedLastSyncAt.coerceAtLeast(0L),
                    "createdAt" to FieldValue.serverTimestamp(),
                    "updatedAt" to FieldValue.serverTimestamp(),
                )
            ).await()
        }

        val snap = try {
            ref.get().await()
        } catch (e: FirebaseFirestoreException) {
            if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                e.code == FirebaseFirestoreException.Code.UNAUTHENTICATED
            ) {
                throw CloudRuleException("registerDevice.get", devicePath, e.code.name, e.message.orEmpty(), e)
            }
            throw e
        }

        if (!snap.exists()) {
            try {
                writeCleanDeviceDoc(0L)
            } catch (e: FirebaseFirestoreException) {
                if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                    e.code == FirebaseFirestoreException.Code.UNAUTHENTICATED
                ) {
                    throw CloudRuleException("registerDevice.create", devicePath, e.code.name, e.message.orEmpty(), e)
                }
                throw e
            }
            return
        }

        // إصلاح وثيقة الجهاز القديمة ذاتيا إذا كانت تفتقد حقل createdAt/model/lastSyncAt أو تحتوي حقولًا إضافية مع الحفاظ على السجلات الفرعية
        if (!isValidDeviceSnapshot(snap)) {
            val existingOwner = snap.getString("ownerId")
            if (existingOwner != uid) {
                throw CloudRuleException(
                    "registerDevice.validate",
                    devicePath,
                    "PERMISSION_DENIED",
                    "ownerId=${existingOwner ?: "null"} لا يطابق $uid",
                )
            }
            val preservedSync = snap.getLong("lastSyncAt")?.coerceAtLeast(0L) ?: 0L
            try {
                ref.delete().await()
                writeCleanDeviceDoc(preservedSync)
            } catch (e: FirebaseFirestoreException) {
                throw CloudRuleException("registerDevice.repair", devicePath, e.code.name, e.message.orEmpty(), e)
            }
            return
        }

        val curName = snap.getString("name")
        val curModel = snap.getString("model")
        val curEnabled = (snap.get("enabled") as? List<*>)?.map { it.toString() } ?: emptyList()
        if (curName != safeName || curModel != safeModel || curEnabled != safeEnabled) {
            try {
                ref.update(
                    mapOf(
                        "name" to safeName,
                        "model" to safeModel,
                        "enabled" to safeEnabled,
                        "updatedAt" to FieldValue.serverTimestamp(),
                    )
                ).await()
            } catch (e: FirebaseFirestoreException) {
                if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED && snap.getString("ownerId") == uid) {
                    val preservedSync = snap.getLong("lastSyncAt")?.coerceAtLeast(0L) ?: 0L
                    runCatching {
                        ref.delete().await()
                        writeCleanDeviceDoc(preservedSync)
                        return
                    }
                }
                if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                    e.code == FirebaseFirestoreException.Code.UNAUTHENTICATED
                ) {
                    throw CloudRuleException("registerDevice.update", devicePath, e.code.name, e.message.orEmpty(), e)
                }
                throw e
            }
        }
    }

    suspend fun markSynced(deviceId: String, at: Long) {
        ensureCapabilityAuthClean()
        val devicePath = "users/$uid/devices/$deviceId"
        val ref = devices().document(deviceId)
        val safeTs = at.coerceAtLeast(0L)
        try {
            ref.update(
                mapOf(
                    "lastSyncAt" to safeTs,
                    "updatedAt" to FieldValue.serverTimestamp(),
                )
            ).await()
        } catch (e: FirebaseFirestoreException) {
            if (e.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                e.code == FirebaseFirestoreException.Code.NOT_FOUND
            ) {
                val snap = runCatching { ref.get().await() }.getOrNull()
                if (snap != null && snap.exists() && snap.getString("ownerId") == uid && !isValidDeviceSnapshot(snap)) {
                    runCatching {
                        val safeName = snap.getString("name")?.trim()?.ifEmpty { null }?.take(100) ?: "هاتف أندرويد"
                        val safeModel = snap.getString("model")?.trim()?.ifEmpty { null }?.take(100) ?: "Android"
                        val safeEnabled = (snap.get("enabled") as? List<*>)
                            ?.mapNotNull { it?.toString() }
                            ?.filter { it in ALLOWED_TYPES }
                            ?.distinct()
                            ?.take(3)
                            ?: ALLOWED_TYPES.toList()
                        ref.delete().await()
                        ref.set(
                            mapOf(
                                "ownerId" to uid,
                                "name" to safeName,
                                "model" to safeModel,
                                "enabled" to safeEnabled,
                                "lastSyncAt" to safeTs,
                                "createdAt" to FieldValue.serverTimestamp(),
                                "updatedAt" to FieldValue.serverTimestamp(),
                            )
                        ).await()
                        return
                    }
                }
                throw CloudRuleException("markSynced", devicePath, e.code.name, e.message.orEmpty(), e)
            }
            throw e
        }
    }

    suspend fun listDevices(): List<DeviceInfo> {
        ensureCapabilityAuthClean()
        return devices().whereEqualTo("ownerId", uid).get().await().documents.map {
            val sync = it.getLong("lastSyncAt")
            DeviceInfo(
                id = it.id,
                name = it.getString("name") ?: it.id,
                model = it.getString("model") ?: "",
                enabled = (it.get("enabled") as? List<*>)?.map { x -> x.toString() } ?: emptyList(),
                lastSyncAt = if (sync != null && sync > 0L) sync else null,
            )
        }.sortedByDescending { it.lastSyncAt ?: 0L }
    }

    suspend fun count(deviceId: String, type: RecordType? = null, from: Long? = null, to: Long? = null): Long {
        ensureCapabilityAuthClean()
        var q: Query = records(deviceId).whereEqualTo("ownerId", uid)
        if (type != null) q = q.whereEqualTo("type", type.id)
        if (from != null) q = q.whereGreaterThanOrEqualTo("ts", from)
        if (to != null) q = q.whereLessThanOrEqualTo("ts", to)
        return try {
            q.count().get(AggregateSource.SERVER).await().count
        } catch (e: FirebaseFirestoreException) {
            if (e.code != FirebaseFirestoreException.Code.FAILED_PRECONDITION) throw e
            val docs = records(deviceId).whereEqualTo("ownerId", uid).get().await().documents
            docs.count { d ->
                val t = d.getString("type")
                val ts = d.getLong("ts") ?: 0L
                (type == null || t == type.id) &&
                    (from == null || ts >= from) &&
                    (to == null || ts <= to)
            }.toLong()
        }
    }

    // ---------- السجلات ----------
    private fun validateRecordForUpload(deviceId: String, rec: EncRecord) {
        require(VALID_ID_REGEX.matches(uid) && uid.length in 1..128) { "معرّف الحساب غير صالح." }
        require(VALID_ID_REGEX.matches(deviceId) && deviceId.length in 1..128) { "معرّف الجهاز غير صالح." }
        require(VALID_ID_REGEX.matches(rec.id) && rec.id.length in 1..128) { "معرّف السجل غير صالح." }
        require(rec.type in ALLOWED_TYPES) { "نوع السجل غير مدعوم (${rec.type})." }
        require(rec.ts in 1L..9_999_999_999_999L) { "توقيت السجل خارج النطاق المسموح (${rec.ts})." }
        require(rec.iv.length in 12..64) { "طول متجه التشفير (IV) غير صالح." }
        require(rec.data.length in 16..MAX_CIPHERTEXT_LEN) {
            "حجم البيانات المشفّرة (${rec.data.length}) يتجاوز الحد المسموح ($MAX_CIPHERTEXT_LEN)."
        }
    }

    private fun writeRecordBatch(deviceId: String, recs: List<EncRecord>, existingIds: Set<String>): com.google.firebase.firestore.WriteBatch {
        val b = db.batch()
        recs.forEach { rec ->
            val ref = records(deviceId).document(rec.id)
            if (rec.id in existingIds) {
                b.update(
                    ref,
                    mapOf(
                        "iv" to rec.iv,
                        "data" to rec.data,
                        "updatedAt" to FieldValue.serverTimestamp(),
                    )
                )
            } else {
                b.set(
                    ref,
                    mapOf(
                        "ownerId" to uid,
                        "deviceId" to deviceId,
                        "type" to rec.type,
                        "ts" to rec.ts,
                        "iv" to rec.iv,
                        "data" to rec.data,
                        "v" to 1,
                        "createdAt" to FieldValue.serverTimestamp(),
                        "updatedAt" to FieldValue.serverTimestamp(),
                    )
                )
            }
        }
        return b
    }

    /** يُستدعى بدفعات ≤ 400. يتحقق من الوثائق مباشرة عبر ref.get() عند تعارض وثائق موجودة مسبقًا دون استعلام whereIn المخالف لقواعد السحابة. */
    suspend fun upload(deviceId: String, recs: List<EncRecord>) {
        require(recs.size <= 400)
        if (recs.isEmpty()) return

        ensureCapabilityAuthClean()
        if (!isVaultCapability() && auth.currentUser != null) {
            runCatching { auth.currentUser?.getIdToken(false)?.await() }
        }

        val uniqueRecs = recs.associateBy { it.id }.values.toList()
        uniqueRecs.forEach { validateRecordForUpload(deviceId, it) }
        val basePath = "users/$uid/devices/$deviceId/records"
        val exactPath = if (uniqueRecs.size == 1) "$basePath/${uniqueRecs[0].id}" else basePath

        // 1) الكتابة التفاؤلية مباشرة بدون قراءات مسبقة (توفر آلاف عمليات القراءة عند رفع الدفعات الجديدة)
        try {
            writeRecordBatch(deviceId, uniqueRecs, emptySet()).commit().await()
            return
        } catch (e: FirebaseFirestoreException) {
            if (e.code != FirebaseFirestoreException.Code.PERMISSION_DENIED &&
                e.code != FirebaseFirestoreException.Code.ALREADY_EXISTS
            ) {
                throw e
            }
            if (!isVaultCapability() && (auth.currentUser == null || auth.currentUser?.uid != uid)) {
                throw CloudRuleException(
                    "uploadBatch.auth",
                    exactPath,
                    "UNAUTHENTICATED",
                    "جلسة المصادقة منتهية أو غير متطابقة",
                    e,
                )
            }

            // 2) فحص السجلات الموجودة مسبقًا عبر القراءة الفردية (allow get) بشكل معزول حتى لا يُفشل سجل واحد بقية الدفعة
            val existingValidIds = HashSet<String>(uniqueRecs.size)
            val malformedOwnedIds = HashSet<String>()
            var firstReadError: FirebaseFirestoreException? = null
            var firstReadErrorPath = exactPath

            coroutineScope {
                for (chunk in uniqueRecs.chunked(25)) {
                    val results = chunk.map { rec ->
                        async {
                            val recPath = "$basePath/${rec.id}"
                            try {
                                Triple(rec, recPath, Result.success(records(deviceId).document(rec.id).get().await()))
                            } catch (t: Throwable) {
                                Triple(rec, recPath, Result.failure<DocumentSnapshot>(t))
                            }
                        }
                    }.awaitAll()

                    for ((rec, recPath, outcome) in results) {
                        val readErr = outcome.exceptionOrNull()
                        if (readErr != null) {
                            if (readErr is FirebaseFirestoreException) {
                                if (firstReadError == null) {
                                    firstReadError = readErr
                                    firstReadErrorPath = recPath
                                }
                            } else {
                                throw readErr
                            }
                            continue
                        }
                        val snap = outcome.getOrNull() ?: continue
                        if (snap.exists()) {
                            if (isValidRecordSnapshot(snap, deviceId, rec)) {
                                existingValidIds.add(rec.id)
                            } else if (snap.getString("ownerId") == uid) {
                                malformedOwnedIds.add(rec.id)
                            }
                        }
                    }
                }
            }

            val capturedReadErr = firstReadError
            if (capturedReadErr != null && uniqueRecs.size == 1) {
                throw CloudRuleException(
                    "uploadRecord.get",
                    firstReadErrorPath,
                    capturedReadErr.code.name,
                    capturedReadErr.message.orEmpty(),
                    capturedReadErr,
                )
            }

            if (malformedOwnedIds.isNotEmpty() && capturedReadErr == null) {
                for (badId in malformedOwnedIds) {
                    val recPath = "$basePath/$badId"
                    try {
                        records(deviceId).document(badId).delete().await()
                    } catch (delErr: FirebaseFirestoreException) {
                        throw CloudRuleException("uploadRecord.repairDelete", recPath, delErr.code.name, delErr.message.orEmpty(), delErr)
                    }
                }
            }

            if (capturedReadErr != null || (existingValidIds.isEmpty() && malformedOwnedIds.isEmpty())) {
                val errToReport = capturedReadErr ?: e
                val errPath = if (capturedReadErr != null) firstReadErrorPath else exactPath
                throw CloudRuleException(
                    if (uniqueRecs.size == 1) "uploadRecord" else "uploadBatch",
                    errPath,
                    errToReport.code.name,
                    errToReport.message.orEmpty(),
                    errToReport,
                )
            }

            try {
                writeRecordBatch(deviceId, uniqueRecs, existingValidIds).commit().await()
            } catch (retryErr: FirebaseFirestoreException) {
                if (retryErr.code == FirebaseFirestoreException.Code.PERMISSION_DENIED ||
                    retryErr.code == FirebaseFirestoreException.Code.UNAUTHENTICATED
                ) {
                    throw CloudRuleException(
                        if (uniqueRecs.size == 1) "uploadRecord.retry" else "uploadBatch.retry",
                        exactPath,
                        retryErr.code.name,
                        retryErr.message.orEmpty(),
                        retryErr,
                    )
                }
                throw retryErr
            }
        }
    }

    suspend fun page(
        deviceId: String, type: RecordType, from: Long?, to: Long?, after: DocumentSnapshot?, size: Long = 50,
    ): PageResult {
        ensureCapabilityAuthClean()
        var q: Query = records(deviceId)
            .whereEqualTo("ownerId", uid)
            .whereEqualTo("type", type.id)
        if (from != null) q = q.whereGreaterThanOrEqualTo("ts", from)
        if (to != null) q = q.whereLessThanOrEqualTo("ts", to)
        q = q.orderBy("ts", Query.Direction.DESCENDING)
        if (after != null) q = q.startAfter(after)
        q = q.limit(size + 1)

        return try {
            val docs = q.get().await().documents
            val hasMore = docs.size > size.toInt()
            val slice = if (hasMore) docs.take(size.toInt()) else docs
            val items = slice.mapNotNull { d ->
                val t = d.getString("type") ?: return@mapNotNull null
                val ts = d.getLong("ts") ?: return@mapNotNull null
                val iv = d.getString("iv") ?: return@mapNotNull null
                val data = d.getString("data") ?: return@mapNotNull null
                EncRecord(d.id, t, ts, iv, data)
            }
            PageResult(items, slice.lastOrNull(), !hasMore)
        } catch (e: FirebaseFirestoreException) {
            if (e.code != FirebaseFirestoreException.Code.FAILED_PRECONDITION) throw e
            val allMatching = records(deviceId).whereEqualTo("ownerId", uid).get().await().documents
                .filter { d ->
                    val t = d.getString("type")
                    val ts = d.getLong("ts") ?: 0L
                    t == type.id &&
                        (from == null || ts >= from) &&
                        (to == null || ts <= to)
                }
                .sortedWith(compareByDescending<DocumentSnapshot> { it.getLong("ts") ?: 0L }.thenBy { it.id })

            val startIdx = if (after == null) {
                0
            } else {
                val idx = allMatching.indexOfFirst { it.id == after.id }
                if (idx >= 0) idx + 1 else allMatching.size
            }

            val slice = allMatching.drop(startIdx).take(size.toInt())
            val items = slice.mapNotNull { d ->
                val t = d.getString("type") ?: return@mapNotNull null
                val ts = d.getLong("ts") ?: return@mapNotNull null
                val iv = d.getString("iv") ?: return@mapNotNull null
                val data = d.getString("data") ?: return@mapNotNull null
                EncRecord(d.id, t, ts, iv, data)
            }
            val exhausted = (startIdx + slice.size) >= allMatching.size
            PageResult(items, slice.lastOrNull(), exhausted)
        }
    }

    // ---------- الحذف ----------
    suspend fun deleteRecord(deviceId: String, id: String) {
        ensureCapabilityAuthClean()
        records(deviceId).document(id).delete().await()
    }

    suspend fun deleteRecords(deviceId: String) {
        ensureCapabilityAuthClean()
        while (true) {
            val snap = records(deviceId).whereEqualTo("ownerId", uid).limit(350).get().await()
            if (snap.isEmpty) break
            val b = db.batch()
            snap.documents.forEach { b.delete(it.reference) }
            b.commit().await()
        }
    }

    suspend fun deleteDevice(deviceId: String) {
        ensureCapabilityAuthClean()
        deleteRecords(deviceId)
        devices().document(deviceId).delete().await()
    }

    /** يتحقق من كلمة المرور، يحذف كل بيانات السحابة، ثم يحذف الحساب وسجل الاسم ذريًا. */
    suspend fun deleteAccount(password: String) {
        ensureCapabilityAuthClean()
        val trimmed = password.trim()
        if (trimmed.isEmpty()) throw UsernameAuthException("يرجى إدخال كلمة المرور لتأكيد الحذف.")
        val fbUser = auth.currentUser

        if (fbUser != null && fbUser.email != null && fbUser.providerData.any { it.providerId == "password" }) {
            fbUser.reauthenticate(EmailAuthProvider.getCredential(fbUser.email!!, trimmed)).await()
        } else if (hasCrypto()) {
            val verifiedKey = unlock(trimmed.toCharArray())
                ?: throw UsernameAuthException("كلمة المرور غير صحيحة.")
            verifiedKey.fill(0)
        }

        val profileSnap = user().get().await()
        val claimedUsernameId = profileSnap.getString("usernameId")

        listDevices().forEach { deleteDevice(it.id) }
        runCatching { cryptoDoc().delete().await() }

        val deletedViaCustomFn = if (fbUser != null) {
            UsernameAuth.deleteCustomAuthAccountIfConfigured(trimmed, auth)
        } else {
            false
        }
        if (!deletedViaCustomFn) {
            val finalBatch = db.batch()
            finalBatch.delete(user())
            if (!claimedUsernameId.isNullOrBlank()) {
                finalBatch.delete(usernameDoc(claimedUsernameId))
            }
            finalBatch.commit().await()
            fbUser?.delete()?.await()
        }
        Session.clear()
    }

    companion object {
        val CHECK_PLAIN = "backup-check-v1".toByteArray()
        val CHECK_AAD = "check".toByteArray()
        val ALLOWED_TYPES = setOf("call", "sms", "clip")
        val DEVICE_KEYS = setOf("ownerId", "name", "model", "enabled", "lastSyncAt", "createdAt", "updatedAt")
        val RECORD_KEYS = setOf("ownerId", "deviceId", "type", "ts", "iv", "data", "v", "createdAt", "updatedAt")
        val VALID_ID_REGEX = Regex("^[a-zA-Z0-9_\\-]+$")
        const val MAX_CIPHERTEXT_LEN = 500_000

        fun isVaultCapabilityId(id: String): Boolean =
            id.length == 50 && id.startsWith("v_") && id.substring(2).all { it in '0'..'9' || it in 'a'..'f' }
    }
}
