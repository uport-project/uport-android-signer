package com.uport.sdk.signer.encryption

import android.app.Activity
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.support.v7.app.AppCompatActivity
import com.uport.sdk.signer.UportSigner
import com.uport.sdk.signer.UportSigner.Companion.ERR_ACTIVITY_DOES_NOT_EXIST
import com.uport.sdk.signer.unpackCiphertext
import javax.crypto.Cipher

class FingerprintAsymmetricProtection : KeyProtection() {

    override
    val alias = "__fingerprint_asymmetric_key_alias__"

    override
    fun genKey(context: Context) {

        generateKey(alias, true)
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
            val (_, encryptedBytes) = ciphertext.unpackCiphertext()

            val cipher = getCipher(Cipher.DECRYPT_MODE, alias)

            if (context is AppCompatActivity) {
                showFingerprintDialog(context, purpose, cipher, { err, cryptoObject ->
                    if (err != null) {
                        callback(err, ByteArray(0))
                    } else {
                        val cleartextBytes = cryptoObject.cipher.doFinal(encryptedBytes)
                        callback(null, cleartextBytes)
                    }
                })
            } else {
                callback(IllegalStateException(ERR_ACTIVITY_DOES_NOT_EXIST), ByteArray(0))
            }
        } catch (ex: Exception) {
            callback(ex, ByteArray(0))
        }
    }


    private lateinit var fingerprintDialog: FingerprintDialog

    private fun showFingerprintDialog(activity: Activity, purpose: String, cipher: Cipher, callback: (err: Exception?, FingerprintManager.CryptoObject) -> Unit) {

        fingerprintDialog = FingerprintDialog.create(purpose)
        if (activity.fragmentManager.findFragmentByTag(FingerprintDialog.TAG_FINGERPRINT_DIALOG) == null) {
            val cryptoObject = FingerprintManager.CryptoObject(cipher)
            fingerprintDialog.init(
                    cryptoObject,
                    object : FingerprintDialog.FingerprintDialogCallbacks {
                        override fun onFingerprintSuccess(cryptoObject: FingerprintManager.CryptoObject) {
                            callback(null, cryptoObject)
                            fingerprintDialog.dismiss()
                        }

                        override fun onFingerprintCancel() {
                            callback(RuntimeException(UportSigner.ERR_AUTH_CANCELED), cryptoObject)
                            fingerprintDialog.dismiss()
                        }

                    }
            )
            fingerprintDialog.show(activity.fragmentManager, FingerprintDialog.TAG_FINGERPRINT_DIALOG)
        }
    }

}