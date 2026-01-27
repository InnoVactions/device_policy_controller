package com.itisnajim.device_policy_controller

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.preference.PreferenceManager
import android.util.Log
import android.view.KeyEvent
import java.io.File
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor


class AppDeviceAdminReceiver : DeviceAdminReceiver() {
    companion object {
        fun log(message: String) = Log.d("dpc::", message)

        fun logToFile(context: Context, message: String) {
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

        private const val KEY_IS_FROM_BOOT_COMPLETED = "is_from_boot_completed"

        fun setIsFromBootCompleted(context: Context, value: Boolean) {
            val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
            sharedPreferences.edit().putBoolean(KEY_IS_FROM_BOOT_COMPLETED, value).apply()
        }

        fun isFromBootCompleted(context: Context): Boolean {
            val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
            return sharedPreferences.getBoolean(KEY_IS_FROM_BOOT_COMPLETED, false)
        }
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        log("onProfileProvisioningComplete")
        val i: Intent? =
            context.packageManager.getLaunchIntentForPackage(context.packageName)
        if (i != null) {
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            context.startActivity(i)
        } else {
            log("Couldn't start activity")
        }
    }

    private fun clearAppData(context: Context) {
        logToFile(context, "--- clearAppData started ---")
        try {
            // Method 1: Using DevicePolicyManager (requires API 28+)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                val adminComponent = ComponentName(context, AppDeviceAdminReceiver::class.java)
                if (dpm.isDeviceOwnerApp(context.packageName)) {
                    logToFile(context, "Is device owner, using clearApplicationUserData")
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        dpm.clearApplicationUserData(adminComponent, context.packageName, { r -> r.run() }, { p, s ->
                            logToFile(context, "Data cleared via DPM for $p: $s")
                        })
                    }
                    return
                }
            }
        } catch (e: Exception) {
            logToFile(context, "Failed to clear data via DPM: ${e.message}")
        }

        try {
            val cacheDir = context.cacheDir
            val appDir = File(cacheDir.parent ?: return)
            if (appDir.exists()) {
                val children = appDir.list()
                if (children != null) {
                    for (s in children) {
                        if (s != "lib") {
                            val deleted = deleteDir(File(appDir, s))
                            logToFile(context, "Manual delete $s: $deleted")
                        }
                    }
                }
            }
            logToFile(context, "Manual cache/storage clearing completed")
        } catch (e: Exception) {
            logToFile(context, "Failed to manually clear data: ${e.message}")
        }
    }

    private fun deleteDir(dir: File?): Boolean {
        if (dir != null && dir.isDirectory) {
            val children = dir.list()
            if (children != null) {
                for (i in children.indices) {
                    val success = deleteDir(File(dir, children[i]))
                    if (!success) {
                        return false
                    }
                }
            }
        }
        return dir?.delete() ?: false
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        val action = intent.action
        val extras = intent.extras
        log("onReceive: action: $action, extras: $extras")

        if (Intent.ACTION_MY_PACKAGE_REPLACED == action) {
            logToFile(context, "App updated, clearing data...")
            clearAppData(context)
        }

        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        val lastVersionCode = prefs.getInt("last_version_code", -1)
        val currentVersionCode = try {
            if (android.os.Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0)).longVersionCode.toInt()
            } else if (android.os.Build.VERSION.SDK_INT >= 28) {
                context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0).versionCode
            }
        } catch (e: Exception) {
            -1
        }

        if (lastVersionCode != -1 && currentVersionCode != lastVersionCode) {
            logToFile(context, "Version change detected ($lastVersionCode -> $currentVersionCode), clearing data...")
            // Clear data but PRESERVE the new version code so we don't loop
            prefs.edit().putInt("last_version_code", currentVersionCode).apply()
            clearAppData(context)
        } else if (lastVersionCode == -1) {
            // First run, just save the version code
            prefs.edit().putInt("last_version_code", currentVersionCode).apply()
        }

        if (DevicePolicyManager.ACTION_MANAGED_PROFILE_PROVISIONED == action || Intent.ACTION_MANAGED_PROFILE_ADDED == action) {
            PreferenceManager.getDefaultSharedPreferences(context)
                .edit().putBoolean("is_provisioned", true).apply()
        }
        if (action == Intent.ACTION_BOOT_COMPLETED) {
            setIsFromBootCompleted(context, true)
            val flutterEngine = FlutterEngine(context.applicationContext)
            flutterEngine.plugins.get(DevicePolicyControllerPlugin::class.java) as DevicePolicyControllerPlugin?
            flutterEngine.dartExecutor.executeDartEntrypoint(DartExecutor.DartEntrypoint.createDefault())
            val channel =
                DevicePolicyControllerPlugin.methodChannel(flutterEngine.dartExecutor.binaryMessenger)
            channel.invokeMethod("handleBootCompleted", null)
        }
    }

}