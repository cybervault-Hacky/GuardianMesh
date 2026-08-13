/*
 * Aegis Android Companion — bounded frame queue.
 *
 * Holds in-memory frames for short-lived delivery to the Nexus
 * transport. The queue is bounded at MAX_QUEUE_SIZE and applies the
 * configured backpressure strategy (default DROP_OLDEST). Frame
 * bytes NEVER leave this queue; they are either drained into the
 * transport or dropped.
 */
package com.guardianmesh.aegis.screen

import com.guardianmesh.aegis.core.AegisConstants
import com.guardianmesh.aegis.core.AegisMetrics
import java.util.ArrayDeque

class BoundedFrameQueue(
    private val maxSize: Int = AegisConstants.MAX_QUEUE_SIZE,
    private val backpressure: Strategy = Strategy.DROP_OLDEST,
) {

    enum class Strategy { DROP_OLDEST, DROP_NEWEST, BLOCK }

    private val items = ArrayDeque<ByteArray>(maxSize)
    private var droppedCount: Long = 0L

    init {
        require(maxSize in 1..AegisConstants.MAX_QUEUE_SIZE) {
            "maxSize out of bounds: $maxSize"
        }
    }

    @Synchronized
    fun push(frame: ByteArray): Boolean {
        return when {
            items.size < maxSize -> {
                items.addLast(frame)
                AegisMetrics.framesQueued()
                true
            }
            backpressure == Strategy.DROP_OLDEST -> {
                items.pollFirst()
                items.addLast(frame)
                droppedCount += 1
                AegisMetrics.framesDropped()
                false
            }
            backpressure == Strategy.DROP_NEWEST -> {
                droppedCount += 1
                AegisMetrics.framesDropped()
                false
            }
            else -> {
                // BLOCK: bounded by maxSize, so we always drop oldest.
                items.pollFirst()
                items.addLast(frame)
                droppedCount += 1
                AegisMetrics.framesDropped()
                false
            }
        }
    }

    @Synchronized
    fun drain(): List<ByteArray> {
        val out = ArrayList<ByteArray>(items.size)
        while (items.isNotEmpty()) {
            out.add(items.pollFirst())
        }
        return out
    }

    @Synchronized
    fun size(): Int = items.size

    @Synchronized
    fun dropped(): Long = droppedCount
}
