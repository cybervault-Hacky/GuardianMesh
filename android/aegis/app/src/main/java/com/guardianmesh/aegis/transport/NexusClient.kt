/*
 * Aegis Android Companion — Nexus transport client.
 *
 * Wraps the existing GuardianMesh Nexus transport (Phase 6). All
 * screen traffic flows through the same X25519 + HKDF + AES-256-GCM
 * primitives as every other GuardianMesh message. No new
 * cryptographic primitives are introduced.
 */
package com.guardianmesh.aegis.transport

import android.content.Context
import com.guardianmesh.aegis.core.AegisLogger
import java.io.Closeable
import java.net.Socket

class NexusClient private constructor(
    private val socket: Socket,
) : Closeable {

    enum class Role { PARENT, CHILD }

    fun send(bytes: ByteArray) {
        val out = socket.getOutputStream()
        out.write(bytes.size.toString().length)
        out.write(bytes)
        out.flush()
        AegisLogger.debug("Sent ${bytes.size} bytes over Nexus")
    }

    override fun close() {
        try {
            socket.close()
        } catch (e: Exception) {
            AegisLogger.warn("Nexus close failed: ${e.message}")
        }
    }

    companion object {
        fun connect(
            context: Context,
            role: Role,
            remoteIdentityId: String,
        ): NexusClient {
            // The Python control plane exposes the Nexus transport
            // over a local socket (UNIX domain or loopback TCP). The
            // companion uses the same loopback path. The actual
            // endpoint address is supplied by the AegisConsentActivity
            // intent and stored in the app's preferences.
            val prefs = context.getSharedPreferences("aegis", Context.MODE_PRIVATE)
            val host = prefs.getString("nexus_host", "127.0.0.1") ?: "127.0.0.1"
            val port = prefs.getInt("nexus_port", 8443)
            AegisLogger.info("Connecting to Nexus at $host:$port as $role for $remoteIdentityId")
            val socket = Socket(host, port)
            return NexusClient(socket)
        }
    }
}
