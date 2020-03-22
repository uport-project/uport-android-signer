package com.uport.sdk.signer

import android.os.Build
import me.uport.sdk.core.decodeBase64
import me.uport.sdk.core.padBase64
import me.uport.sdk.core.toBase64

private const val DELIMITER = "]"

/**
 * packs elements of an encryption operation into a string meant to be saved to disk
 */
fun packCiphertext(vararg data: ByteArray): String =
        data.joinToString(DELIMITER) { it.toBase64().padBase64() }

/**
 * unpacks the elements of an encryption op into individual components so they may be used to decrypt
 */
fun unpackCiphertext(ciphertext: String): List<ByteArray> =
        ciphertext
                .split(DELIMITER)
                .map { it.decodeBase64() }

/**
 * shorthand for checking if this code is running on android M or later
 */
fun hasMarshmallow(): Boolean = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)

/**
 * Callback used by async encryption methods
 */
typealias EncryptionCallback = (err: Exception?, ciphertext: String) -> Unit

/**
 * Callback used by async decryption methods
 */
typealias DecryptionCallback = (err: Exception?, cleartext: ByteArray) -> Unit
