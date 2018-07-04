@file:Suppress("DEPRECATION")

package com.uport.sdk.signer

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import com.uport.sdk.signer.encryption.KeyProtection
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
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


@RunWith(AndroidJUnit4::class)
class KeyStoreTest {

    private lateinit var context: Context
    private var alias = "__key_store_test_key_alias__"

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getTargetContext()
        Security.addProvider(BouncyCastleProvider())
        Security.getProviders().forEach {
            println(it.name)
        }
    }

    fun genSymmetricKey(): SecretKey {
        val gen = KeyGenerator.getInstance("AES")
        gen.init(256, SecureRandom())
        val key = gen.generateKey()

        return key
    }

    fun getAsymmetricCipher(mode: Int, alias: String): Cipher {

        val asymmetricCipher = Cipher.getInstance(KeyProtection.ASYMMETRIC_TRANSFORMATION)

        if (mode == Cipher.WRAP_MODE) {
            generateKey(context, alias, false, -1)
            val publicKey = getKeyStore().getCertificate(alias)?.publicKey!!


            //due to a bug in API23, the public key needs to be separated from the keystore
            val unrestricted = KeyFactory.getInstance(publicKey.algorithm)
                    .generatePublic(X509EncodedKeySpec(publicKey.encoded))

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val spec = OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
                asymmetricCipher.init(mode, unrestricted, spec)
            } else {
                asymmetricCipher.init(mode, unrestricted)
            }

        } else if (mode == Cipher.UNWRAP_MODE) {
            val privateKey = getKeyStore().getKey(alias, null) as PrivateKey
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val spec = OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
                asymmetricCipher.init(mode, privateKey, spec)
            } else {
                asymmetricCipher.init(mode, privateKey)
            }
        }

        return asymmetricCipher
    }

    fun generateKey(context: Context, keyAlias: String, requiresAuth: Boolean = false, sessionTimeout: Int = -1) {

        val keyStore = getKeyStore()

        val publicKey = keyStore.getCertificate(keyAlias)?.publicKey

        if (publicKey == null) {

            val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val purpose = KeyProperties.PURPOSE_DECRYPT
                KeyGenParameterSpec.Builder(keyAlias, purpose)
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

                val specBuilder = KeyPairGeneratorSpec.Builder(context)
                        .setAlias(keyAlias)
                        .setSubject(X500Principal("CN=$keyAlias"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(startDate)
                        .setEndDate(endDate)
                // Only API levels 19 and above allow specifying RSA key parameters.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                    val rsaSpec = RSAKeyGenParameterSpec(KeyProtection.KEY_SIZE, RSAKeyGenParameterSpec.F4)
                    specBuilder.setAlgorithmParameterSpec(rsaSpec)
                    specBuilder.setKeySize(KeyProtection.KEY_SIZE)
                }
                if (requiresAuth) {
                    specBuilder.setEncryptionRequired()
                }
                specBuilder.build()
            }

            val keyPairGenerator = KeyPairGenerator.getInstance("RSA", KeyProtection.ANDROID_KEYSTORE_PROVIDER)
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
        }
    }

    private fun getKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(KeyProtection.ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore
    }

    fun encrypt(data: ByteArray): List<ByteArray> {
        val oneTimeKey = genSymmetricKey()

        val wrappingCipher = getAsymmetricCipher(WRAP_MODE, alias)
        val encKey = wrappingCipher.wrap(oneTimeKey)

        val encryptingCipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        encryptingCipher.init(ENCRYPT_MODE, oneTimeKey)

        val encData = encryptingCipher.doFinal(data)
        val iv = encryptingCipher.iv
        return listOf(encKey, iv, encData)
    }

    fun decrypt(bundle: List<ByteArray>): ByteArray {
        val unwrappingCipher = getAsymmetricCipher(UNWRAP_MODE, alias)
        val (wrappedKey, iv, encData) = bundle
        val oneTimeKey = unwrappingCipher.unwrap(wrappedKey, "AES", SECRET_KEY)

        val decryptingCipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        decryptingCipher.init(DECRYPT_MODE, oneTimeKey, IvParameterSpec(iv))

        return decryptingCipher.doFinal(encData)
    }

    @Test
    fun whateverKS() {

        val textSize = listOf(128, 256, 512, 1024, 2048, 4096, 13, 1234, 6123, 65535)

        textSize.forEach {
            val blob = ByteArray(it)
            Random().nextBytes(blob)

            println("encrypting message of size $it")
            val encBundle = encrypt(blob)
            println("encrypted message of size $it")
            val decBlob = decrypt(encBundle)
            println("decrypted message of size $it")
            assertArrayEquals(" failed to decrypt blob of size $it:", blob, decBlob)
        }

        assertTrue(true)
    }

    @Test
    @Throws(Exception::class)
    fun testWTF() {
        //android testing is weird, some devices need this function to see the test suite
        assertTrue(true)
    }


}