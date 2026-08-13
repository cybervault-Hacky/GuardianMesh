/*
 * Aegis Android Companion — logger.
 *
 * The logger is intentionally minimal. It never logs frame bytes,
 * screenshot blobs, or any captured screen content. Only metadata
 * (session IDs, device IDs, lifecycle transitions) is logged.
 */
package com.guardianmesh.aegis.core

import android.content.Context
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

object AegisLogger {
    private val initialized = AtomicBoolean(false)
    private const val TAG = "Aegis"

    fun init(context: Context) {
        if (initialized.compareAndSet(false, true)) {
            Log.i(TAG, "Aegis logger initialized")
        }
    }

    fun info(message: String) {
        Log.i(TAG, message)
    }

    fun warn(message: String) {
        Log.w(TAG, message)
    }

    fun debug(message: String) {
        Log.d(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) {
            Log.e(TAG, message, throwable)
        } else {
            Log.e(TAG, message)
        }
    }
}
