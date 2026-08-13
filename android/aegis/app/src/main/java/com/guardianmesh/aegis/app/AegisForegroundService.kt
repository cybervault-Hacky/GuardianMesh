/*
 * Aegis Android Companion — foreground service.
 *
 * The foreground service is the child-side visible indicator. It is
 * started ONLY after:
 *   1. the child has explicitly approved a screen view in GuardianMesh, AND
 *   2. the Android MediaProjection system consent dialog has been granted.
 *
 * The service exposes a STOP SHARING action that performs an immediate
 * local cancellation. The action works even if the network is
 * unavailable.
 *
 * The service MUST be stopped the moment the capture session ends for
 * any reason (child stop, parent stop, expiration, trust revocation,
 * transport disconnect).
 */
package com.guardianmesh.aegis.app

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.guardianmesh.aegis.R
import com.guardianmesh.aegis.core.AegisLogger
import com.guardianmesh.aegis.core.AegisMetrics
import com.guardianmesh.aegis.screen.MediaProjectionProvider
import com.guardianmesh.aegis.screen.FrameLimiter
import com.guardianmesh.aegis.screen.AndroidMediaCodecEncoder
import com.guardianmesh.aegis.screen.BoundedFrameQueue
import com.guardianmesh.aegis.transport.NexusClient
import com.guardianmesh.aegis.transport.ScreenTransportAdapter
import com.guardianmesh.aegis.authorization.SystemConsentGate

class AegisForegroundService : Service() {

    private var provider: MediaProjectionProvider? = null
    private var nexus: NexusClient? = null
    private var sessionId: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart(intent)
            ACTION_STOP -> handleStop()
        }
        return START_NOT_STICKY
    }

    private fun handleStart(intent: Intent) {
        val aegisSessionId = intent.getStringExtra(EXTRA_AEGIS_SESSION_ID) ?: return
        val transportSessionId = intent.getStringExtra(EXTRA_TRANSPORT_SESSION_ID) ?: return
        sessionId = aegisSessionId

        // Step 1: Verify system consent is GRANTED. The companion
        // refuses to start without the system grant.
        val gate = SystemConsentGate.create(this)
        if (!gate.isCaptureAllowed(aegisSessionId)) {
            AegisLogger.warn("Refusing to start: system consent not granted.")
            stopSelf()
            return
        }

        // Step 2: Build the visible indicator notification. The
        // notification is ALWAYS visible while the service is running.
        startForeground(
            AegisApplication.FOREGROUND_NOTIFICATION_ID,
            buildNotification()
        )

        // Step 3: Build the capture pipeline.
        val queue = BoundedFrameQueue(maxSize = 30)
        val encoder = AndroidMediaCodecEncoder()
        val limiter = FrameLimiter(maxFps = 10)
        val projection = MediaProjectionProvider.create(this, intent)
        provider = projection

        // Step 4: Connect to the Nexus transport.
        val client = NexusClient.connect(
            context = this,
            role = NexusClient.Role.CHILD,
            remoteIdentityId = intent.getStringExtra(EXTRA_PARENT_ID) ?: return
        )
        nexus = client
        val adapter = ScreenTransportAdapter(
            client = client,
            sessionId = aegisSessionId,
            transportSessionId = transportSessionId,
            queue = queue,
            encoder = encoder,
            limiter = limiter,
            provider = projection,
            metrics = AegisMetrics,
        )
        adapter.start()

        AegisLogger.info("Aegis capture started for session $aegisSessionId")
    }

    private fun handleStop() {
        AegisLogger.info("Aegis capture stopped for session ${sessionId ?: "<unknown>"}")
        provider?.stop()
        nexus?.close()
        AegisMetrics.reset()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun buildNotification(): Notification {
        val stopIntent = Intent(this, AegisForegroundService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, AegisApplication.CHANNEL_ID)
            .setContentTitle(getString(R.string.aegis_notification_title))
            .setContentText(getString(R.string.aegis_notification_body))
            .setSmallIcon(android.R.drawable.ic_menu_camera)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(
                0,
                getString(R.string.aegis_notification_action_stop),
                stopPending,
            )
            .build()
    }

    override fun onDestroy() {
        handleStop()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.guardianmesh.aegis.START"
        const val ACTION_STOP = "com.guardianmesh.aegis.STOP"
        const val EXTRA_AEGIS_SESSION_ID = "aegis_session_id"
        const val EXTRA_TRANSPORT_SESSION_ID = "transport_session_id"
        const val EXTRA_PARENT_ID = "parent_id"
    }
}
