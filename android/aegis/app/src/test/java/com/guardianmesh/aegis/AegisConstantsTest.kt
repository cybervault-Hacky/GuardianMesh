/*
 * Aegis Android Companion — AegisConstants JVM unit tests.
 */
package com.guardianmesh.aegis

import com.guardianmesh.aegis.core.AegisConstants
import org.junit.Assert.assertEquals
import org.junit.Test

class AegisConstantsTest {

    @Test
    fun documented_limits_are_stable() {
        assertEquals(10, AegisConstants.MAX_FPS)
        assertEquals(1280, AegisConstants.MAX_WIDTH)
        assertEquals(720, AegisConstants.MAX_HEIGHT)
        assertEquals(4 * 1024 * 1024, AegisConstants.MAX_FRAME_BYTES)
        assertEquals(30, AegisConstants.MAX_QUEUE_SIZE)
        assertEquals(300, AegisConstants.DEFAULT_MAX_DURATION_SECONDS)
        assertEquals(3600, AegisConstants.HARD_MAX_DURATION_SECONDS)
    }
}
