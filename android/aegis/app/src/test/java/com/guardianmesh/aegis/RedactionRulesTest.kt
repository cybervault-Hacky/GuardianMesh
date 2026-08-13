/*
 * Aegis Android Companion — RedactionRules JVM unit tests.
 */
package com.guardianmesh.aegis

import com.guardianmesh.aegis.security.RedactionRules
import org.junit.Assert.assertTrue
import org.junit.Test

class RedactionRulesTest {

    @Test
    fun forbidden_keys_are_in_the_set() {
        for (key in listOf("password", "private_key", "session_key", "nonce", "ciphertext",
                          "payload", "screenshot", "frame_data", "raw_pixels")) {
            assertTrue(
                "Expected $key in REDACTED_KEYS",
                RedactionRules.REDACTED_KEYS.contains(key)
            )
        }
    }

    @Test
    fun no_remote_control_keys() {
        for (key in listOf("remote_input", "remote_tap", "remote_click", "shell", "command",
                          "exec", "keylog", "keystroke", "microphone", "camera", "gps")) {
            assertTrue(
                "Forbidden key must not appear: $key",
                !RedactionRules.REDACTED_KEYS.contains(key)
            )
        }
    }

    @Test
    fun redact_returns_marker() {
        assertTrue(RedactionRules.redact("any value").startsWith("[REDACTED]"))
    }
}
