/*
 * Aegis Android Companion — FrameLimiter JVM unit tests.
 *
 * These tests run on the JVM (no Android device required) and
 * exercise the core frame-pipeline behaviour.
 */
package com.guardianmesh.aegis

import com.guardianmesh.aegis.screen.FrameLimiter
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FrameLimiterTest {

    @Test
    fun first_frame_is_always_allowed() {
        val limiter = FrameLimiter(maxFps = 10)
        assertTrue(limiter.allow())
    }

    @Test
    fun second_frame_too_quick_is_rejected() {
        val limiter = FrameLimiter(maxFps = 10)
        limiter.allow()
        // Immediately afterwards must reject.
        assertFalse(limiter.allow())
    }

    @Test(expected = IllegalArgumentException::class)
    fun zero_fps_is_rejected() {
        FrameLimiter(maxFps = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun excessive_fps_is_rejected() {
        FrameLimiter(maxFps = 100)
    }

    @Test
    fun reset_restores_initial_state() {
        val limiter = FrameLimiter(maxFps = 10)
        limiter.allow()
        limiter.reset()
        assertTrue(limiter.allow())
    }
}
