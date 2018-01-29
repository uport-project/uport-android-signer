package com.uport.sdk.signer

import android.util.Base64
import org.kethereum.crypto.ECKeyPair
import org.kethereum.extensions.toBytesPadded
import org.kethereum.model.SignatureData
import org.spongycastle.asn1.ASN1EncodableVector
import org.spongycastle.asn1.ASN1Encoding
import org.spongycastle.asn1.ASN1Integer
import org.spongycastle.asn1.DERSequence
import org.walleth.khex.toNoPrefixHexString
import java.io.ByteArrayOutputStream
import java.math.BigInteger

/**
 * Returns the JOSE encoding of the standard signature components (joined by empty string)
 */
fun SignatureData.getJoseEncoded(): String {
    val bos = ByteArrayOutputStream()
    bos.write(this.r.toBytesPadded(32))
    bos.write(this.s.toBytesPadded(32))
    return Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)
}

/**
 * Returns the DER encoding of the standard signature components
 */
fun SignatureData.getDerEncoded(): String {

    val v = ASN1EncodableVector()
    v.add(ASN1Integer(this.r))
    v.add(ASN1Integer(this.s))
    return DERSequence(v)
            .getEncoded(ASN1Encoding.DER)
            .toNoPrefixHexString()
}

private const val DELIMITER = "]"

fun ByteArray.packCiphertext(iv: ByteArray = kotlin.ByteArray(0)): String {
    val encodedIV = Base64.encodeToString(iv, Base64.NO_WRAP)
    val encodedEncData = Base64.encodeToString(this, Base64.NO_WRAP)
    return "$encodedIV$DELIMITER$encodedEncData"
}

fun Pair<ByteArray, ByteArray>.packCiphertext(): String {
    val encodedIV = Base64.encodeToString(this.first, Base64.NO_WRAP)
    val encodedEncData = Base64.encodeToString(this.second, Base64.NO_WRAP)
    return "$encodedIV$DELIMITER$encodedEncData"
}

fun String.unpackCiphertext(): Pair<ByteArray, ByteArray> {
    val components = this.split(DELIMITER)
    val iv = Base64.decode(components[0], Base64.NO_WRAP)
    val encryptedBytes = Base64.decode(components[1], Base64.NO_WRAP)
    return Pair(iv, encryptedBytes)
}


internal fun ECKeyPair.getUncompressedPublicKeyWithPrefix(): ByteArray {
    val pubBytes = this.publicKey.toBytesPadded(UportSigner.UNCOMPRESSED_PUBLIC_KEY_SIZE)
    pubBytes[0] = 0x04
    return pubBytes
}

fun BigInteger.keyToBase64(keySize: Int = 32): String =
        Base64.encodeToString(this.toBytesPadded(keySize), Base64.DEFAULT or Base64.NO_WRAP)