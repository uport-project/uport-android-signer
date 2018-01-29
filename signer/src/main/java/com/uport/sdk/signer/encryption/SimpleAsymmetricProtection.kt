package com.uport.sdk.signer.encryption

import android.content.Context

class SimpleAsymmetricProtection : KeyProtection() {

    override
    val alias = "__simple_asymmetric_key_alias__"

    override
    fun genKey(context: Context) {

        generateKey(alias)

    }

    override
    fun encrypt(context: Context, purpose: String, blob: ByteArray, callback: (err: Exception?, ciphertext: String) -> Unit) {
        try {
            val ciphertext = encryptRaw(blob, alias)
            callback(null, ciphertext)
        } catch (ex: Exception) {
            callback(ex, "")
        }
    }


    override
    fun decrypt(context: Context, purpose: String, ciphertext: String, callback: (err: Exception?, cleartext: ByteArray) -> Unit) {
        try {
            val decryptedBytes = decryptRaw(ciphertext, alias)
            callback(null, decryptedBytes)
        } catch (ex: Exception) {
            callback(ex, ByteArray(0))
        }
    }

}