/*
 * Aegis Android Companion — frame rate limiter.
 *
 * Enforces the documented maximum frame rate (10 FPS default). When
 * a frame arrives sooner than 1/max_fps seconds after the previous
 * one, it is dropped. The limiter is a thin, deterministic gate.
 */
package com.guardianmesh.aegis.screen

import android.os.SystemClock

class FrameLimiter(private val maxFps: Int) {

    init {
        require(maxFps in 1..AegisConstants.MAX_FPS) {
            "maxFps must be in 1..${AegisConstants.MAX_FPS}, got $maxFps"
        }
    }

    private val minIntervalNanos: Long = 1_000_000_000L / maxFps
    private var lastAcceptedNanos: Long = 0L

    @Synchronized
    fun allow(): Boolean {
        val now = SystemClock.elapsedRealtimeNanos()
        if (lastAcceptedNanos == 0L || now - lastAcceptedNanos >= minIntervalNanos) {
            lastAcceptedNanos = now
            return true
        }
        return false
    }

    @Synchronized
    fun reset() {
        lastAcceptedNanos = 0L
    }
}
