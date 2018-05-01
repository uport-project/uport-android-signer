package com.uport.sdk.signer

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.util.Base64
import com.uport.sdk.signer.encryption.KeyProtection
import org.kethereum.bip32.generateKey
import org.kethereum.bip39.Mnemonic
import org.kethereum.crypto.Keys
import org.kethereum.crypto.signMessage
import org.kethereum.model.SignatureData
import org.walleth.khex.prepend0xPrefix
import java.security.SecureRandom

@Suppress("unused")
class UportHDSigner : UportSigner() {

    fun hasSeed(context: Context): Boolean {

        val prefs = context.getSharedPreferences(ETH_ENCRYPTED_STORAGE, MODE_PRIVATE)

        val allSeeds = prefs.all.keys
                .filter({ label -> label.startsWith(SEED_PREFIX) })
                .filter({ hasCorrespondingLevelKey(prefs, it) })

        return allSeeds.isNotEmpty()
    }

    fun createHDSeed(context: Context, level: KeyProtection.Level, callback: (err: Exception?, address: String, pubKey: String) -> Unit) {

        val entropyBuffer = ByteArray(128 / 8)
        SecureRandom().nextBytes(entropyBuffer)

        val seedPhrase = Mnemonic.entropyToMnemonic(entropyBuffer)

        return importHDSeed(context, level, seedPhrase, callback)

    }

    fun importHDSeed(context: Context, level: KeyProtection.Level, phrase: String, callback: (err: Exception?, address: String, pubKey: String) -> Unit) {

        try {
            val seedBuffer = Mnemonic.mnemonicToSeed(phrase)

            val entropyBuffer = Mnemonic.mnemonicToEntropy(phrase)

            val extendedRootKey = generateKey(seedBuffer, UPORT_ROOT_DERIVATION_PATH)

            val keyPair = extendedRootKey.getKeyPair()

            val publicKeyBytes = keyPair.getUncompressedPublicKeyWithPrefix()
            val publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
            val address: String = Keys.getAddress(keyPair).prepend0xPrefix()

            val label = asSeedLabel(address)

            storeEncryptedPayload(context,
                    level,
                    label,
                    entropyBuffer,
                    { err, _ ->

                        //empty memory
                        entropyBuffer.fill(0)

                        if (err != null) {
                            return@storeEncryptedPayload callback(err, "", "")
                        }

                        return@storeEncryptedPayload callback(null, address, publicKeyString)
                    })
        } catch (ex: Exception) {
            return callback(ex, "", "")
        }
    }


    fun signTransaction(context: Context, rootAddress: String, derivationPath: String, txPayload: String, prompt: String, callback: (err: Exception?, sigData: SignatureData) -> Unit) {

        val (encryptionLayer, encryptedEntropy, storageError) = getEncryptionForLabel(context, asSeedLabel(rootAddress))

        if (storageError != null) {
            //storage error is also thrown if the root seed does not exist
            return callback(storageError, EMPTY_SIGNATURE_DATA)
        }

        encryptionLayer.decrypt(context, prompt, encryptedEntropy, { err, entropyBuff ->

            if (err != null) {
                return@decrypt callback(err, EMPTY_SIGNATURE_DATA)
            }

            try {

                val phrase = Mnemonic.entropyToMnemonic(entropyBuff)
                val seed = Mnemonic.mnemonicToSeed(phrase)
                val extendedKey = generateKey(seed, derivationPath)

                val keyPair = extendedKey.getKeyPair()

                val txBytes = Base64.decode(txPayload, Base64.DEFAULT)

                val sigData = signMessage(txBytes, keyPair)
                return@decrypt callback(null, sigData)

            } catch (exception: Exception) {
                return@decrypt callback(exception, EMPTY_SIGNATURE_DATA)
            }

        })

    }

    fun signJwtBundle(context: Context, rootAddress: String, derivationPath: String, data: String, prompt: String, callback: (err: Exception?, sigData: SignatureData) -> Unit) {

        val (encryptionLayer, encryptedEntropy, storageError) = getEncryptionForLabel(context, asSeedLabel(rootAddress))

        if (storageError != null) {
            return callback(storageError, SignatureData())
        }

        encryptionLayer.decrypt(context, prompt, encryptedEntropy, { err, entropyBuff ->
            if (err != null) {
                return@decrypt callback(err, SignatureData())
            }

            try {
                val phrase = Mnemonic.entropyToMnemonic(entropyBuff)
                val seed = Mnemonic.mnemonicToSeed(phrase)
                val extendedKey = generateKey(seed, derivationPath)

                val keyPair = extendedKey.getKeyPair()

                val payloadBytes = Base64.decode(data, Base64.DEFAULT)
                val sig = signJwt(payloadBytes, keyPair)

                return@decrypt callback(null, sig)
            } catch (exception: Exception) {
                return@decrypt callback(err, SignatureData())
            }
        })
    }

    /**
     * Derives the ethereum address and public key using the given [derivationPath] starting from
     * the seed that generated the given [rootAddress]
     *
     * The respective seed must have been previously generated or imported.
     *
     * The results are passed back to the calling code using the provided [callback]
     */
    fun computeAddressForPath(context: Context, rootAddress: String, derivationPath: String, prompt: String, callback: (err: Exception?, address: String, pubKey: String) -> Unit) {

        val (encryptionLayer, encryptedEntropy, storageError) = getEncryptionForLabel(context, asSeedLabel(rootAddress))

        if (storageError != null) {
            return callback(storageError, "", "")
        }

        encryptionLayer.decrypt(context, prompt, encryptedEntropy, { err, entropyBuff ->
            if (err != null) {
                return@decrypt callback(storageError, "", "")
            }

            try {
                val phrase = Mnemonic.entropyToMnemonic(entropyBuff)
                val seed = Mnemonic.mnemonicToSeed(phrase)
                val extendedKey = generateKey(seed, derivationPath)

                val keyPair = extendedKey.getKeyPair()

                val publicKeyBytes = keyPair.getUncompressedPublicKeyWithPrefix()
                val publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
                val address: String = Keys.getAddress(keyPair).prepend0xPrefix()

                return@decrypt callback(null, address, publicKeyString)

            } catch (exception: Exception) {
                return@decrypt callback(err, "", "")
            }
        })


    }

    /**
     * Decrypts the seed that generated the given [rootAddress] and returns it as a mnemonic phrase
     *
     * The respective seed must have been previously generated or imported.
     *
     * The result is passed back to the calling code using the provided [callback]
     */
    fun showHDSeed(context: Context, rootAddress: String, prompt: String, callback: (err: Exception?, phrase: String) -> Unit) {

        val (encryptionLayer, encryptedEntropy, storageError) = getEncryptionForLabel(context, asSeedLabel(rootAddress))

        if (storageError != null) {
            return callback(storageError, "")
        }

        encryptionLayer.decrypt(context, prompt, encryptedEntropy, { err, entropyBuff ->
            if (err != null) {
                return@decrypt callback(storageError, "")
            }

            try {
                val phrase = Mnemonic.entropyToMnemonic(entropyBuff)
                return@decrypt callback(null, phrase)
            } catch (exception: Exception) {
                return@decrypt callback(err, "")
            }
        })
    }

    /**
     * Verifies if a given phrase is a valid mnemonic phrase usable in seed generation
     */
    fun validateMnemonic(phrase: String): Boolean = Mnemonic.validateMnemonic(phrase)

    /**
     * Returns a list of addresses representing the uport roots used as handles for seeds
     */
    fun allHDRoots(context: Context): List<String> {

        val prefs = context.getSharedPreferences(ETH_ENCRYPTED_STORAGE, MODE_PRIVATE)
        //list all stored keys, keep a list off what looks like uport root addresses
        return prefs.all.keys
                .filter({ label -> label.startsWith(SEED_PREFIX) })
                .filter({ hasCorrespondingLevelKey(prefs, it) })
                .map { label: String -> label.substring(SEED_PREFIX.length) }
    }

    companion object {
        const val UPORT_ROOT_DERIVATION_PATH: String = "m/7696500'/0'/0'/0'"
    }
}