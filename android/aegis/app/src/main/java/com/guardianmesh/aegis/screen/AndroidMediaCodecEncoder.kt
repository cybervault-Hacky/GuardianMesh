/*
 * Aegis Android Companion — MediaCodec encoder.
 *
 * Wraps android.media.MediaCodec for production encoding. The codec
 * is configured for H.264 (or a future codec) at the documented
 * resolution and bitrate. The encoder releases its native resources
 * in release().
 *
 * No native dependencies are introduced beyond the Android platform.
 */
package com.guardianmesh.aegis.screen

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import com.guardianmesh.aegis.core.AegisConstants
import com.guardianmesh.aegis.core.AegisLogger
import java.nio.ByteBuffer

class AndroidMediaCodecEncoder {

    private var codec: MediaCodec? = null

    val isReady: Boolean
        get() = codec != null

    fun start(width: Int, height: Int, frameRate: Int) {
        if (width > AegisConstants.MAX_WIDTH || height > AegisConstants.MAX_HEIGHT) {
            throw IllegalArgumentException(
                "Encoder dimensions $width x $height exceed bounds"
            )
        }
        if (frameRate > AegisConstants.MAX_FPS) {
            throw IllegalArgumentException(
                "Encoder fps $frameRate exceeds bound ${AegisConstants.MAX_FPS}"
            )
        }
        val mime = MediaFormat.MIMETYPE_VIDEO_AVC
        val format = MediaFormat.createVideoFormat(mime, width, height).apply {
            setInteger(
                MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface
            )
            setInteger(MediaFormat.KEY_BIT_RATE, 4_000_000)
            setInteger(MediaFormat.KEY_FRAME_RATE, frameRate)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1)
        }
        val created = MediaCodec.createEncoderByType(mime)
        created.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        created.start()
        codec = created
        AegisLogger.info("MediaCodec encoder started at ${width}x${height}@${frameRate}fps")
    }

    fun encode(input: ByteBuffer, presentationTimeUs: Long): ByteBuffer {
        val c = codec ?: error("Encoder not started")
        val index = c.dequeueInputBuffer(10_000)
        if (index >= 0) {
            val buffer = c.getInputBuffer(index) ?: error("No input buffer")
            buffer.clear()
            buffer.put(input)
            c.queueInputBuffer(index, 0, input.limit(), presentationTimeUs, 0)
        }
        val info = MediaCodec.BufferInfo()
        val outputIndex = c.dequeueOutputBuffer(info, 0)
        return if (outputIndex >= 0) {
            c.getOutputBuffer(outputIndex) ?: ByteBuffer.allocate(0)
        } else {
            ByteBuffer.allocate(0)
        }
    }

    fun release() {
        try {
            codec?.stop()
        } catch (e: IllegalStateException) {
            AegisLogger.warn("Encoder stop failed: ${e.message}")
        }
        try {
            codec?.release()
        } catch (e: IllegalStateException) {
            AegisLogger.warn("Encoder release failed: ${e.message}")
        }
        codec = null
        AegisLogger.info("MediaCodec encoder released")
    }
}
