/*
 * Aegis Android Companion — PrivacyGuard JVM unit tests.
 */
package com.guardianmesh.aegis

import com.guardianmesh.aegis.security.PrivacyGuard
import org.junit.Assert.assertThrows
import org.junit.Test

class PrivacyGuardTest {

    @Test
    fun payload_field_is_rejected() {
        assertThrows(IllegalStateException::class.java) {
            PrivacyGuard.assertMetadataOnly("payload_hex")
        }
    }

    @Test
    fun screenshot_field_is_rejected() {
        assertThrows(IllegalStateException::class.java) {
            PrivacyGuard.assertMetadataOnly("screenshot_bytes")
        }
    }

    @Test
    fun metadata_field_is_accepted() {
        PrivacyGuard.assertMetadataOnly("session_id")
        PrivacyGuard.assertMetadataOnly("device_id")
        PrivacyGuard.assertMetadataOnly("state")
    }
}
