package com.uport.sdk.signer

import android.content.Context
import com.uport.sdk.signer.encryption.KeyProtection
import org.kethereum.model.SignatureData
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 *
 * Exposes some HD key provider async methods as coroutines
 */

suspend fun UportHDSigner.createHDSeed(
    context: Context,
    level: KeyProtection.Level
): Pair<String, String> = suspendCoroutine {

    this.createHDSeed(context, level) { err, address, pubKeyBase64 ->
        if (err != null) {
            it.resumeWithException(err)
        } else {
            it.resume(address to pubKeyBase64)
        }
    }
}

/**
 * Extension function that wraps the `UportHDSigner.importHDSeed()` as a coroutine
 */
suspend fun UportHDSigner.importHDSeed(
    context: Context,
    level: KeyProtection.Level,
    phrase: String
): Pair<String, String> = suspendCoroutine {

    this.importHDSeed(context, level, phrase) { err, address, pubKeyBase64 ->
        if (err != null) {
            it.resumeWithException(err)
        } else {
            it.resume(address to pubKeyBase64)
        }
    }
}

/**
 * Extension function that wraps the `UportHDSigner.importHDSeed()` as a coroutine
 * This variant gives access to the error object in the return value
 */
suspend fun UportHDSigner.importHDSeedChecked(
    context: Context,
    level: KeyProtection.Level,
    phrase: String
): Triple<String, String, Exception?> = suspendCoroutine {

    this.importHDSeed(context, level, phrase) { err, address, pubKeyBase64 ->
        it.resume(Triple(address, pubKeyBase64, err))
    }
}

/**
 * Extension function that wraps the `UportHDSigner.signTransaction()` as a coroutine
 */

suspend fun UportHDSigner.signTransaction(
    context: Context,
    rootAddress: String,
    derivationPath: String,
    txPayload: String,
    prompt: String
): SignatureData = suspendCoroutine {

    this.signTransaction(context, rootAddress, derivationPath, txPayload, prompt) { err, sigData ->
        if (err != null) {
            it.resumeWithException(err)
        } else {
            it.resume(sigData)
        }
    }
}

/**
 * Extension function that wraps the `UportHDSigner.signTransaction()` as a coroutine
 * This variant gives access to the error object in the return value
 */

suspend fun UportHDSigner.signTransactionChecked(
    context: Context,
    rootAddress: String,
    derivationPath: String,
    txPayload: String,
    prompt: String
): Pair<SignatureData, java.lang.Exception?> = suspendCoroutine {

    this.signTransaction(context, rootAddress, derivationPath, txPayload, prompt) { err, sigData ->
        it.resume(sigData to err)
    }
}

/**
 * Extension function that wraps the `computeAddressForPath` as a coroutine
 */
suspend fun UportHDSigner.computeAddressForPath(
    context: Context,
    rootAddress: String,
    derivationPath: String,
    prompt: String
): Pair<String, String> = suspendCoroutine {

    this.computeAddressForPath(
        context,
        rootAddress,
        derivationPath,
        prompt
    ) { err, address, pubKeyBase64 ->
        if (err != null) {
            it.resumeWithException(err)
        } else {
            it.resume(address to pubKeyBase64)
        }
    }
}

/**
 * Extension function that wraps the `UportHDSigner.showHDSeed()` as a coroutine
 */
suspend fun UportHDSigner.showHDSeed(
    context: Context,
    rootAddress: String,
    prompt: String
): String = suspendCoroutine {

    this.showHDSeed(context, rootAddress, prompt) { err, phrase ->
        if (err != null) {
            it.resumeWithException(err)
        } else {
            it.resume(phrase)
        }
    }
}