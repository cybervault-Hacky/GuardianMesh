/*
 * Aegis Android Companion — MediaProjection provider.
 *
 * Wraps the Android MediaProjection API. The companion MUST only
 * call this with an intent that carries a system-issued token. The
 * system consent dialog is presented by AegisConsentActivity, which
 * captures the user's response and forwards the token here.
 *
 * No attempt is ever made to bypass the system dialog, to capture
 * without the user's explicit Allow response, or to suppress the
 * system screen-capture indicator. The companion relies entirely on
 * the public android.media.projection API surface.
 */
package com.guardianmesh.aegis.screen

import android.content.Context
import android.content.Intent
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.util.DisplayMetrics
import com.guardianmesh.aegis.core.AegisConstants
import com.guardianmesh.aegis.core.AegisLogger

class MediaProjectionProvider private constructor(
    private val context: Context,
    private val projection: MediaProjection,
) {

    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null

    val isAvailable: Boolean
        get() = virtualDisplay != null

    fun start(width: Int, height: Int, dpi: Int) {
        if (width > AegisConstants.MAX_WIDTH || height > AegisConstants.MAX_HEIGHT) {
            throw IllegalArgumentException(
                "Capture dimensions $width x $height exceed documented bounds"
            )
        }
        imageReader = ImageReader.newInstance(
            width, height, android.graphics.PixelFormat.RGBA_8888, 2
        )
        val flags = DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR
        virtualDisplay = projection.createVirtualDisplay(
            "GuardianMeshAegisCapture",
            width, height, dpi,
            flags,
            imageReader!!.surface,
            null, null
        )
        AegisLogger.info("MediaProjection started at ${width}x${height}")
    }

    fun capture(): android.media.Image? {
        val reader = imageReader ?: return null
        return try {
            reader.acquireLatestImage()
        } catch (e: IllegalStateException) {
            AegisLogger.warn("ImageReader no longer valid: ${e.message}")
            null
        }
    }

    fun stop() {
        virtualDisplay?.release()
        virtualDisplay = null
        imageReader?.close()
        imageReader = null
        projection.stop()
        AegisLogger.info("MediaProjection stopped")
    }

    companion object {
        fun create(context: Context, intent: Intent): MediaProjectionProvider {
            val manager = context.getSystemService(
                Context.MEDIA_PROJECTION_SERVICE
            ) as MediaProjectionManager
            val projection = manager.getMediaProjection(
                RESULT_CODE_EXTRA,
                intent
            ) ?: throw IllegalStateException(
                "MediaProjection token missing or revoked."
            )
            return MediaProjectionProvider(context, projection)
        }

        @Suppress("DEPRECATION")
        private val RESULT_CODE_EXTRA = if (Build.VERSION.SDK_INT >= 33) {
            MediaProjectionManager.EXTRA_MEDIA_PROJECTION_TOKEN
        } else {
            "android.media.projection.extra.EXTRA_MEDIA_PROJECTION"
        }
    }
}
