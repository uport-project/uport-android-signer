@file:Suppress("DEPRECATION")

package com.uport.sdk.signer.encryption

import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.Build.VERSION
import android.os.Build.VERSION_CODES
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.uport.sdk.signer.packCiphertext
import com.uport.sdk.signer.unpackCiphertext
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.Cipher.*
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.security.auth.x500.X500Principal
import javax.security.cert.CertificateException


/**
 * Describes the functionality of encryption layer
 */
abstract class KeyProtection {

    enum class Level {
        /**
         * Requires user authentication within a 30 second time window
         */
        SINGLE_PROMPT,

        /**
         * Requires user authentication using fingerprint or Lockscreen for every use of the key
         */
        PROMPT,

        /**
         * Uses AndroidKeyStore encryption, without user presence requirement
         */
        SIMPLE,

        /**
         * unused yet - defaults to [SIMPLE]
         */
        CLOUD
    }

    abstract fun genKey(context: Context)
    abstract fun encrypt(context: Context, purpose: String = "", blob: ByteArray, callback: (err: Exception?, ciphertext: String) -> Unit)
    abstract fun decrypt(context: Context, purpose: String = "", ciphertext: String, callback: (err: Exception?, cleartext: ByteArray) -> Unit)

    abstract val alias: String

    companion object {
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

        val ASYMMETRIC_TRANSFORMATION =
                if (Build.VERSION.SDK_INT >= VERSION_CODES.M)
                    "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
                else
                    "RSA/ECB/PKCS1Padding"

        fun canUseKeychainAuthentication(context: Context): Boolean {
            val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            // TODO: prompt user to setup keyguard
            return keyguardManager.isKeyguardSecure
        }

        fun hasSetupFingerprint(context: Context): Boolean {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val mFingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
                try {
                    if (!mFingerprintManager.isHardwareDetected) {
                        return false
                    } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
                        //TODO: prompt user to enroll fingerprints
                        return false
                    }
                } catch (e: SecurityException) {
                    // Should never be thrown since we have declared the USE_FINGERPRINT permission
                    // in the manifest file
                    return false
                }

                return true
            } else {
                return false
            }
        }

        fun hasFingerprintHardware(context: Context): Boolean {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val mFingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
                try {
                    mFingerprintManager.isHardwareDetected
                } catch (e: SecurityException) {
                    // Should never be thrown since we have declared the USE_FINGERPRINT permission
                    // in the manifest file
                    false
                }
            } else {
                false
            }
        }

        const val WRAPPING_KEY_SIZE = 2048

        private val OAEP_SPEC = OAEPParameterSpec(
                "SHA-256", "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

        @Throws(KeyPermanentlyInvalidatedException::class,
                KeyStoreException::class,
                CertificateException::class,
                UnrecoverableKeyException::class,
                IOException::class,
                NoSuchAlgorithmException::class,
                InvalidKeyException::class,
                InvalidAlgorithmParameterException::class)
        fun getWrappingCipher(mode: Int, keyAlias: String): Cipher {

            val keyStore = getKeyStore()

            val cipher = getInstance(ASYMMETRIC_TRANSFORMATION)

            val key = when (mode) {
                DECRYPT_MODE, UNWRAP_MODE -> {
                    keyStore.getKey(keyAlias, null) as PrivateKey
                }
            //ENCRYPT_MODE, WRAP_MODE
                else -> {
                    val pubKey = keyStore.getCertificate(keyAlias).publicKey
                    //due to a bug in API23, the public key needs to be separated from the keystore
                    KeyFactory.getInstance(pubKey.algorithm)
                            .generatePublic(X509EncodedKeySpec(pubKey.encoded)) as PublicKey
                }
            }

            if (VERSION.SDK_INT >= VERSION_CODES.M) {
                cipher.init(mode, key, OAEP_SPEC)
            } else {
                cipher.init(mode, key)
            }

            return cipher
        }

        @Throws(KeyStoreException::class,
                NoSuchProviderException::class)
        private fun getKeyStore(): KeyStore {
            // Get a KeyStore instance with the Android Keystore provider.
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)

            // Relict of the old JCA API - you have to call load() even
            // if you do not have an input stream you want to load - otherwise it'll crash.
            keyStore.load(null)
            return keyStore
        }

        @Throws(KeyStoreException::class,
                NoSuchProviderException::class,
                NoSuchAlgorithmException::class,
                InvalidAlgorithmParameterException::class)
        fun generateWrappingKey(context: Context, keyAlias: String, requiresAuth: Boolean = false, sessionTimeout: Int = -1) {

            val keyStore = getKeyStore()

            val publicKey = keyStore.getCertificate(keyAlias)?.publicKey

            if (publicKey == null) {

                val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setUserAuthenticationRequired(requiresAuth)
                            .setUserAuthenticationValidityDurationSeconds(sessionTimeout)
                            .build()
                } else {
                    val cal = Calendar.getInstance()
                    val startDate: Date = cal.time
                    cal.add(Calendar.YEAR, 100)
                    val endDate: Date = cal.time

                    @Suppress("DEPRECATION")
                    val specBuilder = KeyPairGeneratorSpec.Builder(context)
                            .setAlias(keyAlias)
                            .setSubject(X500Principal("CN=$keyAlias"))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(startDate)
                            .setEndDate(endDate)
                    // Only API levels 19 and above allow specifying RSA key parameters.
                    if (VERSION.SDK_INT >= VERSION_CODES.KITKAT) {
                        val rsaSpec = RSAKeyGenParameterSpec(WRAPPING_KEY_SIZE, RSAKeyGenParameterSpec.F4)
                        specBuilder.setAlgorithmParameterSpec(rsaSpec)
                        specBuilder.setKeySize(WRAPPING_KEY_SIZE)
                    }
                    if (requiresAuth) {
                        specBuilder.setEncryptionRequired()
                    }
                    specBuilder.build()
                }

                val keyPairGenerator = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE_PROVIDER)
                keyPairGenerator.initialize(spec)
                keyPairGenerator.generateKeyPair()
            }
        }

        @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
        internal fun encryptRaw(blob: ByteArray, keyAlias: String): String {

            val cipher = getWrappingCipher(ENCRYPT_MODE, keyAlias)

            val encryptedBytes = cipher.doFinal(blob)

            return packCiphertext(encryptedBytes)
        }

        @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
        internal fun decryptRaw(ciphertext: String, keyAlias: String): ByteArray {

            val cipher = getWrappingCipher(DECRYPT_MODE, keyAlias)

            val (encryptedBytes) = unpackCiphertext(ciphertext)

            return cipher.doFinal(encryptedBytes)
        }
    }
}