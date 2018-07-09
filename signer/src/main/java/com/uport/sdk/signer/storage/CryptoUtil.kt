@file:Suppress("DEPRECATION")

package com.uport.sdk.signer.storage

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.uport.sdk.signer.packCiphertext
import com.uport.sdk.signer.unpackCiphertext
import com.uport.sdk.signer.encryption.KeyProtection.Companion.generateWrappingKey
import com.uport.sdk.signer.encryption.KeyProtection.Companion.getWrappingCipher
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Cipher.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


class CryptoUtil(context: Context) {

    private val appContext = context.applicationContext

    private fun getKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore
    }

    //used for symmetric encryption on API 23+
    @TargetApi(Build.VERSION_CODES.M)
    private fun genEncryptionKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER)
        val purpose = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val builder = KeyGenParameterSpec.Builder(keyAlias, purpose)

        builder.setBlockModes(BLOCK_MODE)
                .setKeySize(AES_KEY_SIZE)
                .setEncryptionPaddings(BLOCK_PADDING)

        keyGenerator.init(builder.build())

        return keyGenerator.generateKey()
    }

    private fun genOneTimeKey(): SecretKey {
        val gen = KeyGenerator.getInstance(ALGORITHM_AES)
        gen.init(AES_KEY_SIZE, SecureRandom())

        return gen.generateKey()
    }

    fun encrypt(blob: ByteArray): String {
        val keyStore = getKeyStore()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)

            val secretKey = keyStore.getKey(keyAlias, null) ?: genEncryptionKey()
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedBytes = cipher.doFinal(blob)

            return packCiphertext(cipher.iv, encryptedBytes)
        } else {
            val oneTimeKey = genOneTimeKey()

            //ensure public key exists
            keyStore.getCertificate(keyAlias)?.publicKey ?: generateWrappingKey(appContext, keyAlias)

            val wrappingCipher = getWrappingCipher(WRAP_MODE, keyAlias)
            val wrappedKey = wrappingCipher.wrap(oneTimeKey)

            val encryptingCipher = Cipher.getInstance(AES_TRANSFORMATION)
            encryptingCipher.init(ENCRYPT_MODE, oneTimeKey)
            val encryptedBlob = encryptingCipher.doFinal(blob)

            return packCiphertext(wrappedKey, encryptingCipher.iv, encryptedBlob)
        }
    }


    fun decrypt(ciphertext: String): ByteArray {

        val keyStore = getKeyStore()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

            val secretKey = keyStore.getKey(keyAlias, null) ?: genEncryptionKey()
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)

            val (iv, encryptedBytes) = unpackCiphertext(ciphertext)

            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

            return cipher.doFinal(encryptedBytes)
        } else {
            val wrappingCipher = getWrappingCipher(UNWRAP_MODE, keyAlias)
            val (wrappedKey, iv, encryptedBytes) = unpackCiphertext(ciphertext)

            val encryptionKey = wrappingCipher.unwrap(wrappedKey, ALGORITHM_AES, SECRET_KEY)
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, IvParameterSpec(iv))

            return cipher.doFinal(encryptedBytes)
        }
    }

    companion object {
        private const val keyAlias = "simple_protection_key_alias"
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

        private const val AES_KEY_SIZE = 256

        @SuppressLint("InlinedApi")
        private const val ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES
        @SuppressLint("InlinedApi")
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        @SuppressLint("InlinedApi")
        private const val BLOCK_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7

        private const val AES_TRANSFORMATION = "$ALGORITHM_AES/$BLOCK_MODE/$BLOCK_PADDING"

    }


}