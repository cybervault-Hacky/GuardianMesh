/*
 * Aegis Android Companion — BoundedFrameQueue JVM unit tests.
 */
package com.guardianmesh.aegis

import com.guardianmesh.aegis.screen.BoundedFrameQueue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedFrameQueueTest {

    @Test
    fun queue_accepts_frames_within_bounds() {
        val q = BoundedFrameQueue(maxSize = 3)
        assertTrue(q.push(byteArrayOf(1)))
        assertTrue(q.push(byteArrayOf(2)))
        assertTrue(q.push(byteArrayOf(3)))
        assertEquals(3, q.size())
    }

    @Test
    fun drop_oldest_drops_oldest() {
        val q = BoundedFrameQueue(maxSize = 2, backpressure = BoundedFrameQueue.Strategy.DROP_OLDEST)
        q.push(byteArrayOf(1))
        q.push(byteArrayOf(2))
        q.push(byteArrayOf(3))
        val drained = q.drain()
        assertEquals(2, drained.size)
        assertEquals(2, drained[0][0].toInt())
        assertEquals(3, drained[1][0].toInt())
    }

    @Test
    fun drain_empties_the_queue() {
        val q = BoundedFrameQueue(maxSize = 5)
        q.push(byteArrayOf(1))
        q.push(byteArrayOf(2))
        val drained = q.drain()
        assertEquals(2, drained.size)
        assertEquals(0, q.size())
    }

    @Test(expected = IllegalArgumentException::class)
    fun zero_max_size_rejected() {
        BoundedFrameQueue(maxSize = 0)
    }
}
