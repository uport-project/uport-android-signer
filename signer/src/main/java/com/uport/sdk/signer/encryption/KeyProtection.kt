package com.uport.sdk.signer.encryption

import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.uport.sdk.signer.packCiphertext
import com.uport.sdk.signer.unpackCiphertext
import java.io.IOException
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
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

    @Throws(KeyStoreException::class,
            NoSuchProviderException::class,
            NoSuchAlgorithmException::class,
            InvalidAlgorithmParameterException::class)
    internal fun generateKey(keyAlias: String, requiresAuth: Boolean = false, sessionTimeout: Int = -1) {

        val keyStore = getKeyStore()

        val publicKey = keyStore.getCertificate(keyAlias)?.publicKey

        if (publicKey == null) {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_PROVIDER)
            keyPairGenerator.initialize(
                    KeyGenParameterSpec.Builder(
                            keyAlias,
                            KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setUserAuthenticationRequired(requiresAuth)
                            .setUserAuthenticationValidityDurationSeconds(sessionTimeout)
                            .build())
            keyPairGenerator.generateKeyPair()
        }
    }

    @Throws(KeyPermanentlyInvalidatedException::class,
            KeyStoreException::class,
            CertificateException::class,
            UnrecoverableKeyException::class,
            IOException::class,
            NoSuchAlgorithmException::class,
            InvalidKeyException::class,
            InvalidAlgorithmParameterException::class)
    internal fun getCipher(mode: Int, keyAlias: String): Cipher {

        val keyStore = getKeyStore()

        val cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION)

        if (mode == DECRYPT_MODE) {

            val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey

            cipher.init(mode, privateKey)

        } else if (mode == ENCRYPT_MODE) {

            val publicKey = keyStore.getCertificate(keyAlias).publicKey

            //due to a bug in API23, the public key needs to be separated from the keystore
            val unrestricted = KeyFactory.getInstance(publicKey.algorithm)
                    .generatePublic(X509EncodedKeySpec(publicKey.encoded))

            val spec = OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

            cipher.init(Cipher.ENCRYPT_MODE, unrestricted, spec)
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

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    internal fun encryptRaw(blob: ByteArray, keyAlias: String): String {

        val cipher = getCipher(ENCRYPT_MODE, keyAlias)

        val encryptedBytes = cipher.doFinal(blob)

        return encryptedBytes.packCiphertext()
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    internal fun decryptRaw(ciphertext: String, keyAlias: String): ByteArray {

        val cipher = getCipher(DECRYPT_MODE, keyAlias)

        val (_, encryptedBytes) = ciphertext.unpackCiphertext()

        return cipher.doFinal(encryptedBytes)
    }

    companion object {
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

        const val ASYMMETRIC_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        fun canUseKeychainAuthentication(context: Context): Boolean {
            val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            // TODO: prompt user to setup keyguard
            return keyguardManager.isKeyguardSecure
        }

        fun hasSetupFingerprint(context: Context): Boolean {
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
        }

        fun hasFingerprintHardware(context: Context): Boolean {
            val mFingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
            return try {
                mFingerprintManager.isHardwareDetected
            } catch (e: SecurityException) {
                // Should never be thrown since we have declared the USE_FINGERPRINT permission
                // in the manifest file
                false
            }
        }
    }
}