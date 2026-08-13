/*
 * Aegis Android Companion — error types.
 *
 * The companion raises typed errors that map directly to the Python
 * control plane's AegisError hierarchy. Error messages are
 * metadata only.
 */
package com.guardianmesh.aegis.core

sealed class AegisError(message: String) : RuntimeException(message) {
    class InvalidDimensions(dims: String) :
        AegisError("Invalid capture dimensions: $dims")
    class OversizedDimensions(width: Int, height: Int) :
        AegisError("Oversized dimensions: ${width}x$height")
    class UnsupportedPixelFormat(bytesPerPixel: Int) :
        AegisError("Unsupported pixel format: $bytesPerPixel bytes/px")
    class ConsentDenied : AegisError("System consent denied")
    class ConsentRevoked : AegisError("System consent revoked")
    class AuthorizationMissing : AegisError("GuardianMesh authorization missing")
}
