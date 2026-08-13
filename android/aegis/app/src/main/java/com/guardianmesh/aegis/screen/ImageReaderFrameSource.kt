/*
 * Aegis Android Companion — ImageReader frame source.
 *
 * Bridges the MediaProjection virtual display to the rest of the
 * pipeline. Each call to acquire() returns the latest image (or null
 * if no image is available).
 */
package com.guardianmesh.aegis.screen

import android.media.Image
import android.media.ImageReader

class ImageReaderFrameSource(private val reader: ImageReader) {

    fun acquire(): Image? {
        return try {
            reader.acquireLatestImage()
        } catch (e: IllegalStateException) {
            null
        }
    }

    fun close() {
        try {
            reader.close()
        } catch (e: IllegalStateException) {
            // Reader was already closed; ignore.
        }
    }
}
