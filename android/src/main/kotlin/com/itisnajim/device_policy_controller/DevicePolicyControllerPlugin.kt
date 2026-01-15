package com.itisnajim.device_policy_controller

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.util.Base64
import android.util.Log
import android.view.ViewGroup
import android.view.WindowManager
import com.itisnajim.device_policy_controller.multipreferences.MultiPreferences
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry
import java.io.File


private const val PROVISION_REQUEST_CODE = 1337


/** DevicePolicyControllerPlugin */
class DevicePolicyControllerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var preferences: MultiPreferences
    private lateinit var channel: MethodChannel
    private lateinit var mDevicePolicyManager: DevicePolicyManager
    private lateinit var adminComponentName: ComponentName
    private lateinit var context: Context
    private var activity: Activity? = null
    private var isInitialized = false
    private var adminPrivilegeCallback: ((Boolean) -> Unit)? = null

    companion object {
        fun log(message: String) = Log.d("dpc::", message)
        private const val methodChannelName = "device_policy_controller"
        fun methodChannel(messenger: BinaryMessenger) = MethodChannel(messenger, methodChannelName)

        const val DEVICE_ADMIN_ENABLED_ACTION = "android.app.action.DEVICE_ADMIN_ENABLED"
        const val BOOT_COMPLETED_ACTION = "android.intent.action.BOOT_COMPLETED"
        const val XM_SCAN_ACTION = "com.android.server.scannerservice.broadcast"
        const val SHINIOW_SCAN_ACTION = "com.android.server.scannerservice.shinow"
        const val IDATA_SCAN_ACTION = "android.intent.action.SCANRESULT"
        const val YBX_SCAN_ACTION = "android.intent.ACTION_DECODE_DATA"
        const val PL_SCAN_ACTION = "scan.rcv.message"
        const val BARCODE_DATA_ACTION = "com.ehsy.warehouse.action.BARCODE_DATA"
        const val HONEYWELL_SCAN_ACTION = "com.honeywell.decode.intent.action.EDIT_DATA"
        const val BAR_SCAN_ACTION = "android.intent.ACTION_BAR_SCAN"
        const val DONGTING_BAR_SCAN_ACTION = "com.Dongting.WeScan.intent.action.ACTION_BAR_SCAN"

        val actions = arrayOf(
            DEVICE_ADMIN_ENABLED_ACTION,
            BOOT_COMPLETED_ACTION,
            XM_SCAN_ACTION,
            SHINIOW_SCAN_ACTION,
            IDATA_SCAN_ACTION,
            YBX_SCAN_ACTION,
            YBX_SCAN_ACTION,
            PL_SCAN_ACTION,
            BARCODE_DATA_ACTION,
            HONEYWELL_SCAN_ACTION,
            BAR_SCAN_ACTION,
            DONGTING_BAR_SCAN_ACTION,
        )
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {}
    override fun onDetachedFromActivityForConfigChanges() {}
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        this.activity = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        log("onAttachedToEngine")

        context = binding.applicationContext
        channel = methodChannel(binding.binaryMessenger)
        channel.setMethodCallHandler(this)

        preferences = MultiPreferences("DevicePolicyControllerPlugin", context.contentResolver)


        initializeIfNeeded();
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "setApplicationRestrictions" -> {
                val packageName = call.argument<String>("packageName")
                val restrictions = call.argument<Map<String, String>>("restrictions")
                setApplicationRestrictions(packageName, restrictions, result)
            }

            "getApplicationRestrictions" -> {
                val packageName = call.argument<String>("packageName")
                getApplicationRestrictions(packageName, result)
            }

            "addUserRestrictions" -> {
                val restrictions = call.argument<List<String>>("restrictions")
                addUserRestrictions(restrictions, result)
            }

            "clearUserRestriction" -> {
                val restrictions = call.argument<List<String>>("restrictions")
                clearUserRestriction(restrictions, result)
            }

            "lockDevice" -> {
                val password = call.argument<String>("password")
                lockDevice(password, result)
            }

            "installApplication" -> {
                val apkUrl = call.argument<String>("apkUrl")
                installApplication(apkUrl, result)
            }

            "rebootDevice" -> {
                val reason = call.argument<String>("reason")
                rebootDevice(reason, result)
            }

            "getDeviceInfo" -> getDeviceInfo(result)
            "requestAdminPrivilegesIfNeeded" -> requestAdminPrivilegesIfNeeded(result)
            "setKeepScreenAwake" -> {
                val enable = call.argument<Boolean>("enable")
                setKeepScreenAwake(enable ?: false, result)
            }

            "isScreenAwake" -> isScreenAwake(result)

            "isAdminActive" -> result.success(isAdminActive())
            "lockApp" -> {
                val home = call.argument<Boolean>("home") ?: false
                lockApp(home, result)
            }

            "unlockApp" -> unlockApp(result)

            "isAppLocked" -> result.success(isAppLocked())
            "clearDeviceOwnerApp" -> {
                val packageName = call.argument<String>("packageName")
                clearDeviceOwnerApp(packageName, result)
            }

            "wipeData" -> {
                val flags = call.argument<Int>("flags")
                val reason = call.argument<String>("reason")

                wipeData(flags ?: 0, reason, result)
            }

            "setKeyguardDisabled" -> {
                val disabled = call.argument<Boolean>("disabled")
                setKeyguardDisabled(disabled ?: true, result)
            }

            "setScreenCaptureDisabled" -> {
                val disabled = call.argument<Boolean>("disabled")
                setScreenCaptureDisabled(disabled ?: true, result)
            }

            "setCameraDisabled" -> {
                val disabled = call.argument<Boolean>("disabled")
                setCameraDisabled(disabled ?: true, result)
            }

            "setAsLauncher" -> {
                val enable = call.argument<Boolean>("enable")
                setAsLauncher(enable ?: false, result)
            }

            "startApp" -> {
                val packageName = call.argument<String>("packageName")
                startApp(packageName, result)
            }

            "get" -> {
                val contentKey = call.argument<String>("contentKey")
                val default = call.argument<String>("default")
                get(contentKey!!, default, result)
            }

            "put" -> {
                val contentKey = call.argument<String>("contentKey")
                val content = call.argument<String>("content")
                put(contentKey!!, content, result)
            }

            "remove" -> {
                val contentKey = call.argument<String>("contentKey")
                remove(contentKey!!, result)
            }

            "clear" -> clear(result)

            else -> result.notImplemented()
        }
    }


    private fun startApp(packageName: String?, result: Result) {
        val intent =
            context.packageManager.getLaunchIntentForPackage(packageName ?: context.packageName)
        if (intent != null) {
            // intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            context.startActivity(intent)
            result.success(true)
        } else {
            // Package not found.
            result.success(false)
        }
    }


    private fun setKeyguardDisabled(disabled: Boolean, result: Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mDevicePolicyManager.setKeyguardDisabled(adminComponentName, disabled)
                result.success(null)
            } catch (e: SecurityException) {
                result.error("SET_KEYGUARD_DISABLED", e.localizedMessage, null)
            }
        } else {
            result.error(
                "SET_KEYGUARD_DISABLED",
                "Setting keyguard disabled is not supported on this Android version.",
                null
            )
        }
    }

    private fun setScreenCaptureDisabled(disabled: Boolean, result: Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                mDevicePolicyManager.setScreenCaptureDisabled(adminComponentName, disabled)
                result.success(null)
            } catch (e: SecurityException) {
                result.error("SET_SCREEN_CAPTURE_DISABLED", e.localizedMessage, null)
            }
        } else {
            result.error(
                "SET_SCREEN_CAPTURE_DISABLED",
                "Setting screen capture disabled is not supported on this Android version.",
                null
            )
        }
    }

    private fun setCameraDisabled(disabled: Boolean, result: Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mDevicePolicyManager.setCameraDisabled(adminComponentName, disabled)
                result.success(null)
            } catch (e: SecurityException) {
                result.error("SET_CAMERA_DISABLED", e.localizedMessage, null)
            }
        } else {
            result.error(
                "SET_CAMERA_DISABLED",
                "Setting camera disabled is not supported on this Android version.",
                null
            )
        }
    }


    private fun bundleToMap(extras: Bundle): Map<String, String?> {
        val map: MutableMap<String, String?> = HashMap()
        val ks = extras.keySet()
        val iterator: Iterator<String> = ks.iterator()
        while (iterator.hasNext()) {
            val key = iterator.next()
            map[key] = extras.getString(key)
        }
        return map
    }

    private fun setApplicationRestrictions(
        packageName: String?,
        restrictions: Map<String, String>?,
        result: Result
    ) {
        if (restrictions != null) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    val bundle = Bundle()
                    restrictions.entries.forEach {
                        bundle.putString(it.key, it.value)
                    }

                    mDevicePolicyManager.setApplicationRestrictions(
                        adminComponentName, packageName, bundle
                    )
                }
                result.success(null)
            } catch (e: Exception) {
                result.error("SET_APPLICATION_RESTRICTIONS", e.localizedMessage, null)
            }
        } else {
            result.error(
                "INVALID_ARGUMENTS",
                "The 'packageName' argument is null or invalid",
                null
            )
        }
    }


    private fun getApplicationRestrictions(packageName: String?, result: Result) {
        if (packageName != null) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    val bundle = mDevicePolicyManager.getApplicationRestrictions(
                        adminComponentName,
                        packageName
                    )
                    result.success(bundleToMap(bundle))
                }
                result.success(null)
            } catch (e: Exception) {
                result.error("GET_APPLICATION_RESTRICTIONS", e.localizedMessage, null)
            }
        } else {
            result.error(
                "INVALID_ARGUMENTS",
                "The 'packageName' argument is null or invalid",
                null
            )
        }
    }

    private fun addUserRestrictions(restrictions: List<String>?, result: Result) {
        if (restrictions != null) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    restrictions.forEach {
                        mDevicePolicyManager.addUserRestriction(
                            adminComponentName, it
                        )
                    }
                }

                result.success(true) // Return the appropriate result value
            } catch (e: Exception) {
                result.error("ADD_USER_RESTRICTIONS_FAILED", e.localizedMessage, null)
            }
        } else {
            result.error(
                "INVALID_ARGUMENTS",
                "The 'restrictions' argument is null or invalid",
                null
            )
        }
    }

    private fun clearUserRestriction(restrictions: List<String>?, result: Result) {
        if (restrictions != null) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    restrictions.forEach {
                        mDevicePolicyManager.clearUserRestriction(
                            adminComponentName, it
                        )
                    }
                }

                result.success(true) // Return the appropriate result value
            } catch (e: Exception) {
                result.error("CLEAR_USER_RESTRICTIONS_FAILED", e.localizedMessage, null)
            }
        } else {
            result.error(
                "INVALID_ARGUMENTS",
                "The 'restrictions' argument is null or invalid",
                null
            )
        }
    }

    private fun lockDevice(password: String?, result: Result) {
        if (!password.isNullOrEmpty()) {
            mDevicePolicyManager.setPasswordQuality(
                adminComponentName,
                DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED
            )
            val passwordBytes = Base64.decode(password, Base64.NO_WRAP)
            var res = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (mDevicePolicyManager.isResetPasswordTokenActive(adminComponentName)) {
                    mDevicePolicyManager.resetPasswordWithToken(
                        adminComponentName, null, passwordBytes, 0
                    )
                    res = true
                } else {
                    // Try to set again token
                    // On Android 8+, set reset password token if not active
                    res = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                        !mDevicePolicyManager.isResetPasswordTokenActive(adminComponentName)
                    ) {
                        mDevicePolicyManager.setResetPasswordToken(
                            adminComponentName, passwordBytes
                        )
                        true
                    } else false
                }
            } // else Cannot for Android 7 or less

            mDevicePolicyManager.setPasswordQuality(
                adminComponentName,
                DevicePolicyManager.PASSWORD_QUALITY_SOMETHING
            )

            result.success(res)

        } else {
            mDevicePolicyManager.lockNow()
            result.success(true)
        }
    }

    // Add this as a class member
    private var installResultReceiver: BroadcastReceiver? = null

    // Add this method to handle installation results
    private fun registerInstallReceiver() {
        if (installResultReceiver != null) {
            return // Already registered
        }

        installResultReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
                val sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)

                logToFile("[InstallReceiver] Installation callback received")
                logToFile("[InstallReceiver] Session ID: $sessionId")
                logToFile("[InstallReceiver] Status code: $status")

                when (status) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        logToFile("[InstallReceiver] STATUS_PENDING_USER_ACTION - This shouldn't happen for device owner")
                        val confirmIntent = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        if (confirmIntent != null) {
                            confirmIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(confirmIntent)
                        }
                    }
                    PackageInstaller.STATUS_SUCCESS -> {
                        logToFile("[InstallReceiver] ✓ Installation SUCCESS!")
                        // Optionally notify your Dart code
                        channel.invokeMethod("onInstallSuccess", null)
                    }
                    PackageInstaller.STATUS_FAILURE -> {
                        logToFile("[InstallReceiver] ✗ Installation FAILED")
                        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                        logToFile("[InstallReceiver] Failure message: $message")
                    }
                    PackageInstaller.STATUS_FAILURE_ABORTED -> {
                        logToFile("[InstallReceiver] ✗ Installation ABORTED")
                    }
                    PackageInstaller.STATUS_FAILURE_BLOCKED -> {
                        logToFile("[InstallReceiver] ✗ Installation BLOCKED")
                        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                        logToFile("[InstallReceiver] Blocked reason: $message")
                    }
                    PackageInstaller.STATUS_FAILURE_CONFLICT -> {
                        logToFile("[InstallReceiver] ✗ Installation CONFLICT")
                    }
                    PackageInstaller.STATUS_FAILURE_INCOMPATIBLE -> {
                        logToFile("[InstallReceiver] ✗ Installation INCOMPATIBLE")
                    }
                    PackageInstaller.STATUS_FAILURE_INVALID -> {
                        logToFile("[InstallReceiver] ✗ Installation INVALID APK")
                    }
                    PackageInstaller.STATUS_FAILURE_STORAGE -> {
                        logToFile("[InstallReceiver] ✗ Installation STORAGE ERROR")
                    }
                    else -> {
                        logToFile("[InstallReceiver] Unknown status: $status")
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction("com.sunvig.companion.INSTALL_ACTION") // Your custom action
        }

        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(installResultReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(installResultReceiver, filter)
        }

        logToFile("Install result receiver registered")
    }

    private fun logToFile(message: String) {
        try {
            val logFile = File(context.getExternalFilesDir(null), "dpc_install.log")
            val timestamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.getDefault()).format(java.util.Date())
            logFile.appendText("[$timestamp] $message\n")

            // Also log to logcat
            log(message)
        } catch (e: Exception) {
            log("Failed to write to log file: ${e.message}")
        }
    }

    private fun installApplication(apkUrl: String?, result: Result) {
        logToFile("=== installApplication called ===")
        logToFile("apkUrl: $apkUrl")

        if (!apkUrl.isNullOrEmpty()) {
            try {
                logToFile("Android SDK version: ${Build.VERSION.SDK_INT}")

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    val isDeviceOwner = mDevicePolicyManager.isDeviceOwnerApp(context.packageName)
                    logToFile("Is device owner: $isDeviceOwner")
                    logToFile("Package name: ${context.packageName}")

                    if (!isDeviceOwner) {
                        logToFile("ERROR: Not a device owner!")
                        result.error("INSTALL_APPLICATION_FAILED", "App is not a device owner", null)
                        return
                    }

                    val uri = Uri.parse(apkUrl)
                    logToFile("Parsed URI: $uri")
                    logToFile("URI scheme: ${uri.scheme}")

                    val packageInstaller = context.packageManager.packageInstaller
                    logToFile("Got package installer")

                    val params = android.content.pm.PackageInstaller.SessionParams(
                        android.content.pm.PackageInstaller.SessionParams.MODE_FULL_INSTALL
                    )
                    logToFile("Created session params")

                    val sessionId = packageInstaller.createSession(params)
                    logToFile("Created session ID: $sessionId")

                    val session = packageInstaller.openSession(sessionId)
                    logToFile("Opened session")

                    logToFile("Starting background download thread...")
                    Thread {
                        try {
                            logToFile("[Thread] Download thread started")
                            logToFile("[Thread] Connecting to: $apkUrl")

                            val input = if (uri.scheme == "http" || uri.scheme == "https") {
                                logToFile("[Thread] Opening HTTP/HTTPS connection")
                                val url = java.net.URL(apkUrl)
                                val connection = url.openConnection() as java.net.HttpURLConnection

                                if (connection is javax.net.ssl.HttpsURLConnection) {
                                    logToFile("[Thread] Setting up SSL for self-signed cert")
                                    val trustAllCerts = arrayOf<javax.net.ssl.TrustManager>(
                                        object : javax.net.ssl.X509TrustManager {
                                            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate>? = null
                                            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                                            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                                        }
                                    )
                                    val sslContext = javax.net.ssl.SSLContext.getInstance("SSL")
                                    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
                                    connection.sslSocketFactory = sslContext.socketFactory
                                    connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                                }

                                logToFile("[Thread] Connecting...")
                                connection.connect()
                                logToFile("[Thread] Connected! Response code: ${connection.responseCode}")
                                logToFile("[Thread] Response message: ${connection.responseMessage}")
                                logToFile("[Thread] Content length: ${connection.contentLength}")

                                if (connection.responseCode != 200) {
                                    logToFile("[Thread] ERROR: Bad response code ${connection.responseCode}")
                                    session.abandon()
                                    return@Thread
                                }

                                connection.inputStream
                            } else {
                                logToFile("[Thread] Opening content resolver stream")
                                context.contentResolver.openInputStream(uri)
                            }

                            if (input == null) {
                                logToFile("[Thread] ERROR: Input stream is null!")
                                session.abandon()
                                return@Thread
                            }

                            logToFile("[Thread] Got input stream, opening output stream")
                            val output = session.openWrite("package", 0, -1)
                            logToFile("[Thread] Output stream opened, starting copy...")

                            var totalBytes = 0L
                            input.use { inputStream ->
                                output.use { outputStream ->
                                    val buffer = ByteArray(8192)
                                    var bytesRead: Int
                                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                                        outputStream.write(buffer, 0, bytesRead)
                                        totalBytes += bytesRead

                                        if (totalBytes % (1024 * 1024) == 0L) {
                                            logToFile("[Thread] Downloaded: ${totalBytes / 1024 / 1024} MB")
                                        }
                                    }
                                    logToFile("[Thread] Copy complete! Total bytes: $totalBytes")
                                    session.fsync(outputStream)
                                    logToFile("[Thread] fsync complete")
                                }
                            }

                            logToFile("[Thread] Creating pending intent")
                            val intent = Intent("com.sunvig.companion.INSTALL_ACTION").apply {
                                setPackage(context.packageName)
                            }
                            val pendingIntent = android.app.PendingIntent.getBroadcast(
                                context,
                                sessionId,
                                intent,
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                                    android.app.PendingIntent.FLAG_MUTABLE
                                else 0
                            )

                            logToFile("[Thread] Committing session...")
                            session.commit(pendingIntent.intentSender)
                            logToFile("[Thread] Session committed")

                            session.close()
                            logToFile("[Thread] Session closed - Installation should start now!")

                        } catch (e: Exception) {
                            logToFile("[Thread] === EXCEPTION IN DOWNLOAD THREAD ===")
                            logToFile("[Thread] Exception type: ${e.javaClass.name}")
                            logToFile("[Thread] Exception message: ${e.message}")
                            logToFile("[Thread] Stack trace: ${e.stackTraceToString()}")
                            session.abandon()
                            logToFile("[Thread] Session abandoned")
                        }
                    }.start()

                    logToFile("Background thread started, returning success to Dart")
                    result.success(true)
                } else {
                    logToFile("ERROR: Android version too old (${Build.VERSION.SDK_INT})")
                    result.error("INSTALL_APPLICATION_FAILED", "Silent installation requires Android 5.0+", null)
                }
            } catch (e: Exception) {
                logToFile("=== EXCEPTION IN MAIN FUNCTION ===")
                logToFile("Exception type: ${e.javaClass.name}")
                logToFile("Exception message: ${e.message}")
                logToFile("Stack trace: ${e.stackTraceToString()}")
                result.error("INSTALL_APPLICATION_FAILED", e.localizedMessage, null)
            }
        } else {
            logToFile("ERROR: apkUrl is null or empty")
            result.error("INVALID_ARGUMENTS", "The 'apkUrl' argument is null or empty", null)
        }
    }

    @SuppressLint("MissingPermission")
    private fun rebootDevice(reason: String?, result: Result) {
        try {
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            powerManager.reboot(reason)
            result.success(true) // Return the appropriate result value
        } catch (e: Exception) {
            result.error("REBOOT_DEVICE_FAILED", e.localizedMessage, null)
        }
    }

    private fun getDeviceInfo(result: Result) {
        try {
            val deviceInfoMap = HashMap<String, Any>()
            deviceInfoMap["model"] = Build.MODEL
            deviceInfoMap["manufacturer"] = Build.MANUFACTURER
            deviceInfoMap["brand"] = Build.BRAND
            deviceInfoMap["product"] = Build.PRODUCT
            deviceInfoMap["device"] = Build.DEVICE
            deviceInfoMap["board"] = Build.BOARD
            deviceInfoMap["display"] = Build.DISPLAY
            deviceInfoMap["hardware"] = Build.HARDWARE
            deviceInfoMap["id"] = Build.ID
            deviceInfoMap["fingerprint"] = Build.FINGERPRINT
            deviceInfoMap["serial"] = Build.SERIAL
            deviceInfoMap["osVersion"] = Build.VERSION.SDK_INT
            deviceInfoMap["osRelease"] = Build.VERSION.RELEASE
            deviceInfoMap["sdkVersion"] = Build.VERSION.SDK_INT
            deviceInfoMap["type"] = Build.TYPE
            deviceInfoMap["tags"] = Build.TAGS
            result.success(deviceInfoMap) // Return the appropriate result value
        } catch (e: Exception) {
            result.error("GET_DEVICE_INFO_FAILED", e.localizedMessage, null)
        }
    }

    private fun initializeIfNeeded() {
        if (!isInitialized) {
            try {
                val appDeviceAdminReceiver = AppDeviceAdminReceiver()
                /*appDeviceAdminReceiver.setBootCompletedCallback {
                    log("setBootCompletedCallback")
                    instance.channel.invokeMethod("handleBootCompleted", null)
                }*/
                val intentFilter = IntentFilter()
                actions.forEach { intentFilter.addAction(it) }
                log("actions: ${actions.joinToString(", ")}}")
                context.registerReceiver(appDeviceAdminReceiver, intentFilter)
                adminComponentName = appDeviceAdminReceiver.getWho(context)
                log("registerReceiver packageName: " + adminComponentName.packageName + ", className: " + adminComponentName.className)
                mDevicePolicyManager =
                    context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

                val fromBootCompleted = AppDeviceAdminReceiver.isFromBootCompleted(context);
                log("fromBootCompleted $fromBootCompleted")
                if (fromBootCompleted) {
                    channel.invokeMethod("handleBootCompleted", null)
                    AppDeviceAdminReceiver.setIsFromBootCompleted(context, false)
                }
                registerInstallReceiver()

            } catch (e: Exception) {
            }
        }

        isInitialized = true
    }

    private fun requestAdminPrivilegesIfNeeded(callback: (Boolean) -> Unit) {
        adminPrivilegeCallback = callback
        val isDeviceOwnerApp = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            mDevicePolicyManager.isDeviceOwnerApp(adminComponentName.packageName)
        } else false


        if (!isDeviceOwnerApp) {
            adminPrivilegeCallback?.invoke(false)
            adminPrivilegeCallback = null
            return
        }

        if (!isAdminActive()) {
            val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponentName)
            intent.putExtra(
                DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE,
                context.packageName
            )

            intent.putExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME,
                context.packageName
            )

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, true)
                intent.putExtra(
                    DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                    adminComponentName
                )
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_USER_CONSENT, true)
            }

            intent.putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Administrator privileges are required for this app."
            )
            activity?.finish()
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
            activity?.startActivityForResult(intent, PROVISION_REQUEST_CODE)
        } else {
            log("Device admin privilege already granted.")
            adminPrivilegeCallback?.invoke(true)
            adminPrivilegeCallback = null
        }
    }

    private fun requestAdminPrivilegesIfNeeded(result: Result) {
        requestAdminPrivilegesIfNeeded { isPrivilegeGranted ->
            result.success(isPrivilegeGranted)
        }
    }

    private fun setKeepScreenAwake(enable: Boolean, result: Result) {
        if (activity == null) return result.error(
            "A foreground activity is required.",
            "setKeepScreenAwake requires a foreground activity",
            null
        )
        if (enable) {
            activity!!.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            activity!!.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
        result.success(null)
    }

    private fun isScreenAwake(result: Result) {
        if (activity == null) {
            result.error(
                "A foreground activity is required.",
                "isScreenAwake requires a foreground activity",
                null
            )
            return
        }

        val flags = activity!!.window.attributes.flags
        val isAwake = flags and WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON != 0
        result.success(isAwake)
    }

    private fun isAdminActive(): Boolean {
        val devicePolicyManager = mDevicePolicyManager
        val adminComponent = adminComponentName

        return devicePolicyManager.isAdminActive(adminComponent)
    }

    private fun clearDeviceOwnerApp(packageName: String?, result: Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mDevicePolicyManager.clearDeviceOwnerApp(packageName ?: context.packageName)
        }
        result.success(null)
    }

    private fun resetPreferredLauncherAndOpenChooser(context: Context) {
        val packageManager = context.packageManager
        val activityComponent = ComponentName(context, activity!!::class.java)
        packageManager.setComponentEnabledSetting(
            activityComponent,
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            PackageManager.DONT_KILL_APP
        )
        val selector = Intent(Intent.ACTION_MAIN)
        selector.addCategory(Intent.CATEGORY_HOME)
        selector.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        context.startActivity(selector)
        packageManager.setComponentEnabledSetting(
            activityComponent,
            PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
            PackageManager.DONT_KILL_APP
        )
    }

    private fun isAppLauncherDefault(): Boolean {
        val intent = Intent(Intent.ACTION_MAIN)
        intent.addCategory(Intent.CATEGORY_HOME)
        val resolveInfo =
            context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        val currentHomePackage = resolveInfo?.activityInfo?.packageName

        return currentHomePackage == context.packageName;
    }

    private fun get(contentKey: String, defaultValue: String?, result: Result) {
        val value = preferences.getString(contentKey, defaultValue)
        log("get contentKey: $contentKey, value: $value")
        result.success(value)
    }

    private fun put(contentKey: String, content: String?, result: Result) {
        log("put contentKey: $contentKey, content: $content")
        preferences.setString(contentKey, content ?: "")
        result.success(null)
    }

    private fun remove(contentKey: String, result: Result) {
        log("remove contentKey: $contentKey")
        preferences.removePreference(contentKey)
        result.success(null)
    }

    private fun clear(result: Result) {
        preferences.clearPreferences()
        result.success(null)
    }


    private fun setAsLauncher(enable: Boolean, result: Result) {
        val isAdminActive = this.isAdminActive()
        val isAppLauncherDefault = this.isAppLauncherDefault()

        if (enable && isAppLauncherDefault || !enable && !isAppLauncherDefault) {
            result.success(true)
            return
        }

        if (isAdminActive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            if (!isAppLauncherDefault) {
                val activity = this.activity ?: run { result.success(false); return }
                val activityComponent = ComponentName(context, activity::class.java)
                val filter = IntentFilter(Intent.ACTION_MAIN).apply {
                    addCategory(Intent.CATEGORY_HOME)
                    addCategory(Intent.CATEGORY_DEFAULT)
                }
                mDevicePolicyManager.addPersistentPreferredActivity(
                    adminComponentName, filter, activityComponent
                )
            } else {
                mDevicePolicyManager.clearPackagePersistentPreferredActivities(
                    adminComponentName, context.packageName
                )
            }
            result.success(true); return
        } else if (!isAdminActive) {
            if (!isAppLauncherDefault) {
                resetPreferredLauncherAndOpenChooser(context)
            } else {
                context.packageManager.clearPackagePreferredActivities(context.packageName)
                val intent = Intent(Intent.ACTION_MAIN).apply {
                    addCategory(Intent.CATEGORY_HOME)
                }
                context.startActivity(intent)
            }
            result.success(true); return
        }
        result.success(false); return
    }

    private fun lockApp(home: Boolean, result: Result?) {
        if (activity == null) {
            result?.success(false)
            return
        }
        val isAdminActive = isAdminActive()
        if (isAdminActive) {
            // Set the activity as the preferred option for the device.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                val activityComponent = ComponentName(context, activity!!::class.java)
                val intentFilter = IntentFilter(Intent.ACTION_MAIN)
                intentFilter.addCategory(Intent.CATEGORY_DEFAULT)
                if (home) {
                    intentFilter.addCategory(Intent.CATEGORY_HOME)
                }
                mDevicePolicyManager.addPersistentPreferredActivity(
                    adminComponentName,
                    intentFilter,
                    activityComponent
                )

                mDevicePolicyManager.setLockTaskPackages(
                    adminComponentName,
                    arrayOf(context.packageName)
                )
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                try {
                    activity!!.startLockTask()
                    result?.success(true)
                } catch (e: IllegalArgumentException) {
                    result?.success(false)
                    return
                }
            }

            result?.success(true)

        } else {
            // ensures that startLockTask() will not throw
            // see https://stackoverflow.com/questions/27826431/activity-startlocktask-occasionally-throws-illegalargumentexception
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                activity!!.findViewById<ViewGroup>(android.R.id.content).getChildAt(0).post {
                    try {
                        activity!!.startLockTask()
                        result?.success(true)
                    } catch (e: IllegalArgumentException) {
                        result?.success(false)
                    }
                }
            } else result?.success(false)
        }
    }

    private fun unlockApp(result: Result) {
        if (activity == null) {
            result.success(false)
            return
        }
        if (isAdminActive()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                activity!!.stopLockTask()
                //mDevicePolicyManager.clearDeviceOwnerApp(context.packageName);
                result.success(true)
                return
            }

        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                activity!!.stopLockTask()
                result.success(true)
                return
            }
        }
        result.success(false)
    }

    private fun isAppLocked(): Boolean {
        activity?.let { activity ->
            val service = activity.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                ?: return false

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return service.lockTaskModeState == ActivityManager.LOCK_TASK_MODE_LOCKED
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                return service.isInLockTaskMode
            }
            return false
        }
        return false
    }

    private fun wipeData(flags: Int, reason: String?, result: Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && reason != null) {
            mDevicePolicyManager.wipeData(flags, reason)
        } else {
            mDevicePolicyManager.wipeData(flags)
        }
        result.success(null)
    }


    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode == PROVISION_REQUEST_CODE) {
            // Check if the result is OK (admin privilege request was successful)
            if (resultCode == Activity.RESULT_OK) {
                // Notify the callback that admin privilege was granted
                // The callback will proceed with the next steps in the `start` function
                adminPrivilegeCallback?.invoke(true)
            } else {
                // Notify the callback that admin privilege request was denied or cancelled
                adminPrivilegeCallback?.invoke(false)
            }
        }
        return false
    }

}
