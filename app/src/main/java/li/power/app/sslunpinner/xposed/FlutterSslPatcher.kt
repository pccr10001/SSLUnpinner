package li.power.app.sslunpinner.xposed

import android.util.Log
import java.io.File
import java.io.RandomAccessFile

/**
 * Patches libflutter.so to disable SSL certificate verification.
 *
 * Flutter uses BoringSSL (native C/C++) for TLS, completely bypassing Java's
 * TrustManager/SSLContext. This patcher finds the `ssl_verify_peer_cert` function
 * in the binary using byte patterns and patches it to always return 0 (success).
 *
 * Byte patterns are sourced from:
 * https://github.com/NVISOsecurity/disable-flutter-tls-verification
 */
object FlutterSslPatcher {

    private const val TAG = "SSLUnpinner"

    // Return-0 instructions per architecture
    private val RETURN_ZERO_ARM64 = byteArrayOf(
        0x00, 0x00, 0x80.toByte(), 0x52,  // MOV W0, #0
        0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte()  // RET
    )
    private val RETURN_ZERO_ARM32 = byteArrayOf(
        0x00, 0x20,  // MOVS R0, #0
        0x70, 0x47   // BX LR
    )
    private val RETURN_ZERO_X86_X64 = byteArrayOf(
        0x31, 0xC0.toByte(),  // XOR EAX, EAX
        0xC3.toByte()         // RET
    )

    // Patterns per architecture (from the Frida script)
    // Uses hex strings with ?? for wildcard nibbles
    private val PATTERNS_ARM64 = listOf(
        "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
        "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
        "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
        "FF C3 01 D1 FD 7B 01 A9 6A A1 0B 94 08 0A 80 52 48 00 00 39 1A 50 40 F9 DA 02 00 B4 48 03 40 F9"
    )

    private val PATTERNS_ARM32 = listOf(
        "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8"
    )

    private val PATTERNS_X64 = listOf(
        "55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? ?? 0? 00 00 4D 85 ?? 74 1? 4D 8B",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
        "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 30 48 8B 98 D0 01 00 00 48 85 DB"
    )

    private val PATTERNS_X86 = listOf(
        "55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 8B 7D 08 8B 17 8B 42 18 8B 80 88 01"
    )

    /**
     * Detects the device CPU architecture from system properties.
     */
    fun detectArch(): String {
        val abi = System.getProperty("os.arch") ?: ""
        return when {
            abi.contains("aarch64") || abi.contains("arm64") -> "arm64"
            abi.contains("arm") -> "arm"
            abi.contains("x86_64") || abi.contains("amd64") -> "x64"
            abi.contains("x86") || abi.contains("i686") || abi.contains("i386") -> "x86"
            else -> abi
        }
    }

    /**
     * Copies srcFile to dstFile, scans for ssl_verify_peer_cert using byte patterns,
     * and patches it to return 0.
     *
     * @return true if at least one pattern was found and patched
     */
    fun patchLibrary(srcFile: File, dstFile: File, arch: String): Boolean {
        val patterns = when (arch) {
            "arm64" -> PATTERNS_ARM64
            "arm" -> PATTERNS_ARM32
            "x64" -> PATTERNS_X64
            "x86" -> PATTERNS_X86
            else -> {
                Log.w(TAG, "Flutter: unsupported architecture: $arch")
                return false
            }
        }

        val returnZero = when (arch) {
            "arm64" -> RETURN_ZERO_ARM64
            "arm" -> RETURN_ZERO_ARM32
            else -> RETURN_ZERO_X86_X64
        }

        // Copy the library file
        try {
            srcFile.inputStream().use { input ->
                dstFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Flutter: failed to copy libflutter.so: ${e.message}")
            return false
        }

        // Read the file into memory for scanning
        val fileBytes = try {
            dstFile.readBytes()
        } catch (e: Exception) {
            Log.e(TAG, "Flutter: failed to read copied libflutter.so: ${e.message}")
            return false
        }

        var patched = false

        for (patternStr in patterns) {
            val compiledPattern = compilePattern(patternStr)
            val offsets = scanForPattern(fileBytes, compiledPattern)

            for (offset in offsets) {
                Log.i(TAG, "Flutter: ssl_verify_peer_cert found at offset 0x${offset.toString(16)} (pattern: ${patternStr.take(20)}...)")
                try {
                    RandomAccessFile(dstFile, "rw").use { raf ->
                        raf.seek(offset.toLong())
                        raf.write(returnZero)
                    }
                    patched = true
                    Log.i(TAG, "Flutter: ssl_verify_peer_cert patched at offset 0x${offset.toString(16)}")
                } catch (e: Exception) {
                    Log.e(TAG, "Flutter: failed to patch at offset 0x${offset.toString(16)}: ${e.message}")
                }
            }

            // Stop after first matching pattern
            if (patched) break
        }

        if (!patched) {
            Log.w(TAG, "Flutter: no ssl_verify_peer_cert pattern matched — possibly not a Flutter app or patterns outdated")
            // Clean up
            dstFile.delete()
        }

        return patched
    }

    // --- Pattern matching engine ---

    /**
     * A compiled pattern entry: value to match and mask.
     * If mask bit is 0, that nibble is a wildcard.
     */
    private data class PatternByte(val value: Int, val mask: Int)

    /**
     * Compiles a hex pattern string like "F? 0F 1C F8 ?? 5? 01 A9"
     * into a list of PatternByte with masks.
     *
     * - "FF" → value=0xFF, mask=0xFF (exact match)
     * - "F?" → value=0xF0, mask=0xF0 (high nibble must be F, low nibble wildcard)
     * - "??" → value=0x00, mask=0x00 (full wildcard)
     * - "?F" → value=0x0F, mask=0x0F (high nibble wildcard, low nibble must be F)
     */
    private fun compilePattern(pattern: String): List<PatternByte> {
        return pattern.trim().split("\\s+".toRegex()).map { token ->
            require(token.length == 2) { "Invalid pattern token: $token" }
            val highChar = token[0]
            val lowChar = token[1]

            val highValue: Int
            val highMask: Int
            if (highChar == '?') {
                highValue = 0
                highMask = 0
            } else {
                highValue = Character.digit(highChar, 16) shl 4
                highMask = 0xF0
            }

            val lowValue: Int
            val lowMask: Int
            if (lowChar == '?') {
                lowValue = 0
                lowMask = 0
            } else {
                lowValue = Character.digit(lowChar, 16)
                lowMask = 0x0F
            }

            PatternByte(highValue or lowValue, highMask or lowMask)
        }
    }

    /**
     * Scans a byte array for all occurrences of a compiled pattern.
     * Returns a list of offsets where the pattern matches.
     */
    private fun scanForPattern(data: ByteArray, pattern: List<PatternByte>): List<Int> {
        val results = mutableListOf<Int>()
        if (pattern.isEmpty() || data.size < pattern.size) return results

        val limit = data.size - pattern.size
        outer@ for (i in 0..limit) {
            for (j in pattern.indices) {
                val byte = data[i + j].toInt() and 0xFF
                val p = pattern[j]
                if ((byte and p.mask) != p.value) {
                    continue@outer
                }
            }
            results.add(i)
        }
        return results
    }
}
