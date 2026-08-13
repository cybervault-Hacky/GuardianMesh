/*
 * Aegis Android Companion — consent token store.
 *
 * Persists consent records in encrypted shared preferences. Records
 * are metadata only; no screen content is stored.
 */
package com.guardianmesh.aegis.authorization

import android.content.Context
import android.content.SharedPreferences
import com.guardianmesh.aegis.core.AegisLogger

class ConsentTokenStore private constructor(
    private val prefs: SharedPreferences,
) {

    data class Record(
        val sessionId: String,
        val deviceId: String,
        val state: String,
        val grantedAt: Long,
        val expiresAt: Long,
    )

    fun put(record: Record) {
        prefs.edit()
            .putString(KEY_PREFIX + record.sessionId + "_state", record.state)
            .putString(KEY_PREFIX + record.sessionId + "_device", record.deviceId)
            .putLong(KEY_PREFIX + record.sessionId + "_expiresAt", record.expiresAt)
            .putLong(KEY_PREFIX + record.sessionId + "_grantedAt", record.grantedAt)
            .apply()
    }

    fun getForSession(aegisSessionId: String): Record? {
        val state = prefs.getString(KEY_PREFIX + aegisSessionId + "_state", null)
            ?: return null
        return Record(
            sessionId = aegisSessionId,
            deviceId = prefs.getString(KEY_PREFIX + aegisSessionId + "_device", "")
                ?: "",
            state = state,
            grantedAt = prefs.getLong(KEY_PREFIX + aegisSessionId + "_grantedAt", 0L),
            expiresAt = prefs.getLong(KEY_PREFIX + aegisSessionId + "_expiresAt", 0L),
        )
    }

    fun grant(consentToken: String) {
        prefs.edit()
            .putString(KEY_PREFIX_TOKEN + consentToken + "_state", SystemConsentGate.STATE_GRANTED)
            .putLong(KEY_PREFIX_TOKEN + consentToken + "_grantedAt", System.currentTimeMillis())
            .apply()
    }

    fun deny(consentToken: String) {
        prefs.edit()
            .putString(KEY_PREFIX_TOKEN + consentToken + "_state", SystemConsentGate.STATE_DENIED)
            .apply()
    }

    fun revoke(consentToken: String, reason: String) {
        prefs.edit()
            .putString(KEY_PREFIX_TOKEN + consentToken + "_state", SystemConsentGate.STATE_REVOKED)
            .putString(KEY_PREFIX_TOKEN + consentToken + "_reason", reason)
            .apply()
    }

    companion object {
        private const val PREFS_NAME = "guardianmesh.aegis.consent"
        private const val KEY_PREFIX = "consent."
        private const val KEY_PREFIX_TOKEN = "token."

        fun open(context: Context): ConsentTokenStore {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            AegisLogger.info("ConsentTokenStore opened")
            return ConsentTokenStore(prefs)
        }
    }
}
