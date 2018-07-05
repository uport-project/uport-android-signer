@file:Suppress("DEPRECATION")

package com.uport.sdk.signer.storage

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.uport.sdk.signer.packCiphertext
import com.uport.sdk.signer.unpackCiphertext
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.Cipher.SECRET_KEY
import javax.crypto.Cipher.UNWRAP_MODE
import javax.crypto.Cipher.WRAP_MODE
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.security.auth.x500.X500Principal


class CryptoUtil(context: Context) {

    private val appContext = context.applicationContext

    private fun genKey(): Key {

        val keyStore = getKeyStore()

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyStore.getKey(keyAlias, null) ?: genSymmetricKey()
        } else {
            keyStore.getCertificate(keyAlias)?.publicKey ?: genWrappingKey()
        }
    }

    //used for symmetric encryption on API 23+
    @TargetApi(Build.VERSION_CODES.M)
    private fun genSymmetricKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER)
        val purpose = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val builder = KeyGenParameterSpec.Builder(keyAlias, purpose)

        builder.setBlockModes(BLOCK_MODE)
                .setKeySize(AES_KEY_SIZE)
                .setEncryptionPaddings(BLOCK_PADDING)

        keyGenerator.init(builder.build())

        return keyGenerator.generateKey()
    }

    //used for hybrid encryption on older droids
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private fun genWrappingKey(): PublicKey {

        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val purpose = KeyProperties.PURPOSE_DECRYPT
            KeyGenParameterSpec.Builder(keyAlias, purpose)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setUserAuthenticationRequired(false)
                    .setUserAuthenticationValidityDurationSeconds(-1)
                    .setKeySize(WRAPPING_KEY_SIZE)
                    .build()
        } else {

            val cal = Calendar.getInstance()
            val startDate: Date = cal.time
            cal.add(Calendar.YEAR, 100)
            val endDate: Date = cal.time

            @Suppress("DEPRECATION")
            val specBuilder = KeyPairGeneratorSpec.Builder(appContext)
                    .setAlias(keyAlias)
                    .setSubject(X500Principal("CN=$keyAlias"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(startDate)
                    .setEndDate(endDate)
            // Only API levels 19 and above allow specifying RSA key parameters.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                val rsaSpec = RSAKeyGenParameterSpec(WRAPPING_KEY_SIZE, RSAKeyGenParameterSpec.F4)
                specBuilder.setAlgorithmParameterSpec(rsaSpec)
                specBuilder.setKeySize(WRAPPING_KEY_SIZE)
            }

            specBuilder.build()
        }

        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE_PROVIDER)
        keyPairGenerator.initialize(spec)
        return keyPairGenerator.genKeyPair().public
    }

    private fun getKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore
    }

    private fun genOneTimeKey(): SecretKey {
        val gen = KeyGenerator.getInstance(ALGORITHM_AES)
        gen.init(AES_KEY_SIZE, SecureRandom())

        return gen.generateKey()
    }

    private fun getWrappingCipher(mode: Int, alias: String): Cipher {

        val asymmetricCipher = Cipher.getInstance(WRAPPING_TRANSFORMATION)


        when (mode) {
            WRAP_MODE, ENCRYPT_MODE -> {
                val key = genKey()

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val spec = OAEPParameterSpec(
                            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

                    //due to a bug in API23, the public key needs to be isolated from the keystore
                    val isolatedKey = KeyFactory.getInstance(key.algorithm)
                            .generatePublic(X509EncodedKeySpec(key.encoded))

                    asymmetricCipher.init(mode, isolatedKey, spec)
                } else {
                    asymmetricCipher.init(mode, key)
                }

            }
            UNWRAP_MODE, DECRYPT_MODE -> {
                val privateKey = getKeyStore().getKey(alias, null) as PrivateKey
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val spec = OAEPParameterSpec(
                            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
                    asymmetricCipher.init(mode, privateKey, spec)
                } else {
                    asymmetricCipher.init(mode, privateKey)
                }
            }
        }

        return asymmetricCipher
    }

    fun encrypt(blob: ByteArray): String {
        val keyStore = getKeyStore()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)

            val secretKey = keyStore.getKey(keyAlias, null) ?: genKey() as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedBytes = cipher.doFinal(blob)

            return packCiphertext(cipher.iv, encryptedBytes)
        } else {
            val oneTimeKey = genOneTimeKey()

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

            val secretKey = keyStore.getKey(keyAlias, null) ?: genKey() as SecretKey
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


        private const val WRAPPING_KEY_SIZE = 2048
        private const val WRAPPING_TRANSFORMATION = "RSA/ECB/PKCS1Padding"

    }


}