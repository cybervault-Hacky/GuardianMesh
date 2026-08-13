/*
 * Aegis Android Companion — system consent gate.
 *
 * Records the Android system consent grant for a screen session and
 * decides whether capture is allowed. The companion enforces the
 * three-key consent gate:
 *
 *   1. Trust (Phase 2): the device is in the trusted registry.
 *   2. Authorization (Phase 7): the child has approved the view in
 *      GuardianMesh.
 *   3. System consent (Phase 8): the child has tapped "Allow" in the
 *      Android system MediaProjection dialog.
 *
 * Capture is forbidden unless all three are present and unexpired.
 */
package com.guardianmesh.aegis.authorization

import android.content.Context
import com.guardianmesh.aegis.core.AegisLogger

class SystemConsentGate private constructor(
    private val tokens: ConsentTokenStore,
) {

    fun isCaptureAllowed(aegisSessionId: String): Boolean {
        val record = tokens.getForSession(aegisSessionId) ?: return false
        if (record.state != STATE_GRANTED) {
            AegisLogger.warn("Consent not granted for $aegisSessionId (state=${record.state})")
            return false
        }
        if (record.expiresAt < System.currentTimeMillis()) {
            AegisLogger.warn("Consent expired for $aegisSessionId")
            return false
        }
        return true
    }

    fun requestConsent(aegisSessionId: String, deviceId: String, expiresAt: Long) {
        tokens.put(
            ConsentTokenStore.Record(
                sessionId = aegisSessionId,
                deviceId = deviceId,
                state = STATE_REQUESTED,
                grantedAt = 0L,
                expiresAt = expiresAt,
            )
        )
        AegisLogger.info("System consent requested for $aegisSessionId")
    }

    fun grantConsent(consentToken: String) {
        tokens.grant(consentToken)
        AegisLogger.info("System consent granted (token=$consentToken)")
    }

    fun denyConsent(consentToken: String) {
        tokens.deny(consentToken)
        AegisLogger.info("System consent denied (token=$consentToken)")
    }

    fun revokeConsent(consentToken: String, reason: String) {
        tokens.revoke(consentToken, reason)
        AegisLogger.info("System consent revoked (token=$consentToken, reason=$reason)")
    }

    companion object {
        const val STATE_REQUESTED = "REQUESTED"
        const val STATE_GRANTED = "GRANTED"
        const val STATE_DENIED = "DENIED"
        const val STATE_REVOKED = "REVOKED"
        const val STATE_EXPIRED = "EXPIRED"

        fun create(context: Context): SystemConsentGate {
            return SystemConsentGate(ConsentTokenStore.open(context))
        }
    }
}
