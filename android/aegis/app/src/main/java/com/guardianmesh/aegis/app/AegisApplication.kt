/*
 * Aegis Android Companion — application class.
 *
 * Initializes the application-wide logger and the foreground-service
 * notification channel. The AegisForegroundService is started only
 * after the user has explicitly approved a screen view request AND
 * the Android MediaProjection system consent dialog has been granted.
 */
package com.guardianmesh.aegis.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.guardianmesh.aegis.R
import com.guardianmesh.aegis.core.AegisLogger

class AegisApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AegisLogger.init(this)
        ensureNotificationChannel()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.aegis_notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.aegis_notification_channel_description)
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "guardianmesh.aegis.capture"
        const val FOREGROUND_NOTIFICATION_ID = 8421
    }
}
