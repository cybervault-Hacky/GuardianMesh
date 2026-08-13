/*
 * Aegis Android Companion — frame normalizer.
 *
 * Validates the dimensions and pixel format of a captured frame and
 * rejects anything outside the documented bounds. The normalizer
 * never re-encodes; it only validates.
 */
package com.guardianmesh.aegis.screen

import com.guardianmesh.aegis.core.AegisConstants
import com.guardianmesh.aegis.core.AegisError

class FrameNormalizer {

    fun normalize(width: Int, height: Int, bytesPerPixel: Int): IntArray {
        if (width <= 0 || height <= 0) {
            throw AegisError.InvalidDimensions("$width x $height")
        }
        if (width > AegisConstants.MAX_WIDTH || height > AegisConstants.MAX_HEIGHT) {
            throw AegisError.OversizedDimensions(width, height)
        }
        if (bytesPerPixel !in setOf(3, 4)) {
            throw AegisError.UnsupportedPixelFormat(bytesPerPixel)
        }
        return intArrayOf(width, height, bytesPerPixel)
    }
}
