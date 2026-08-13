/*
 * Aegis Android Companion — metrics.
 *
 * Bounded counters and timing aggregates. Metrics NEVER contain
 * frame bytes, screenshot blobs, or any captured screen content.
 *
 * The companion exposes these metrics through Android's tracing
 * API (for diagnostics) and through the Nexus transport (for the
 * parent-side diagnostics view).
 */
package com.guardianmesh.aegis.core

import java.util.concurrent.atomic.AtomicLong

object AegisMetrics {
    private val _framesCaptured = AtomicLong(0)
    private val _framesEncoded = AtomicLong(0)
    private val _framesTransmitted = AtomicLong(0)
    private val _framesDropped = AtomicLong(0)
    private val _transportFailures = AtomicLong(0)
    private val _encoderFailures = AtomicLong(0)

    fun framesCaptured() { _framesCaptured.incrementAndGet() }
    fun framesEncoded() { _framesEncoded.incrementAndGet() }
    fun framesTransmitted() { _framesTransmitted.incrementAndGet() }
    fun framesDropped() { _framesDropped.incrementAndGet() }
    fun transportFailures() { _transportFailures.incrementAndGet() }
    fun encoderFailures() { _encoderFailures.incrementAndGet() }

    fun reset() {
        _framesCaptured.set(0)
        _framesEncoded.set(0)
        _framesTransmitted.set(0)
        _framesDropped.set(0)
        _transportFailures.set(0)
        _encoderFailures.set(0)
    }

    fun snapshot(): Map<String, Long> = mapOf(
        "frames_captured" to _framesCaptured.get(),
        "frames_encoded" to _framesEncoded.get(),
        "frames_transmitted" to _framesTransmitted.get(),
        "frames_dropped" to _framesDropped.get(),
        "transport_failures" to _transportFailures.get(),
        "encoder_failures" to _encoderFailures.get(),
    )
}
