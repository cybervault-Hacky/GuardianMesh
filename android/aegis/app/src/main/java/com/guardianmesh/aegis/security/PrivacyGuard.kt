/*
 * Aegis Android Companion — privacy guard.
 *
 * Defensive helper that rejects any attempt to log, persist, or
 * transmit frame bytes. The privacy guard is invoked at every
 * boundary in the pipeline.
 */
package com.guardianmesh.aegis.security

object PrivacyGuard {

    private val FORBIDDEN_PATTERNS = setOf(
        "screenshot",
        "frame",
        "pixel",
        "bitmap",
        "image_data",
        "raw_pixels",
        "encoded_video",
        "payload_hex",
    )

    fun assertMetadataOnly(fieldName: String) {
        if (FORBIDDEN_PATTERNS.any { fieldName.lowercase().contains(it) }) {
            throw IllegalStateException(
                "Forbidden field name for metadata: $fieldName"
            )
        }
    }

    fun assertNoPayloadField(payload: Map<String, Any>) {
        for (key in payload.keys) {
            assertMetadataOnly(key)
        }
    }
}
