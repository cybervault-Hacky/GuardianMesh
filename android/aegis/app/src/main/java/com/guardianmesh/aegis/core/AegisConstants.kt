/*
 * Aegis Android Companion — constants.
 *
 * The hard limits defined here are the same as the Python control
 * plane's documented limits. They are non-negotiable.
 */
package com.guardianmesh.aegis.core

object AegisConstants {
    /** Maximum frames per second. */
    const val MAX_FPS: Int = 10

    /** Maximum capture width in pixels. */
    const val MAX_WIDTH: Int = 1280

    /** Maximum capture height in pixels. */
    const val MAX_HEIGHT: Int = 720

    /** Maximum encoded frame size in bytes. */
    const val MAX_FRAME_BYTES: Int = 4 * 1024 * 1024

    /** Maximum number of buffered frames. */
    const val MAX_QUEUE_SIZE: Int = 30

    /** Default maximum session duration in seconds. */
    const val DEFAULT_MAX_DURATION_SECONDS: Int = 300

    /** Hard cap for maximum session duration in seconds. */
    const val HARD_MAX_DURATION_SECONDS: Int = 3600
}
