package com.uport.sdk.signer

import android.util.Base64
import org.kethereum.crypto.ECKeyPair
import org.kethereum.crypto.Keys.PRIVATE_KEY_SIZE
import org.kethereum.extensions.toBytesPadded
import org.kethereum.model.SignatureData
import org.spongycastle.asn1.ASN1EncodableVector
import org.spongycastle.asn1.ASN1Encoding
import org.spongycastle.asn1.ASN1Integer
import org.spongycastle.asn1.DERSequence
import org.walleth.khex.toNoPrefixHexString
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.*


const val SIG_COMPONENT_SIZE = PRIVATE_KEY_SIZE

/**
 * Returns the JOSE encoding of the standard signature components (joined by empty string)
 */
fun SignatureData.getJoseEncoded(): String {
    val bos = ByteArrayOutputStream()
    bos.write(this.r.toBytesPadded(SIG_COMPONENT_SIZE))
    bos.write(this.s.toBytesPadded(SIG_COMPONENT_SIZE))
    return Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP or Base64.NO_PADDING or Base64.URL_SAFE)
}

fun String.decodeJose(recoveryParam: Byte = 27): SignatureData = listOf(this)
        .map { Base64.decode(it, Base64.URL_SAFE) }
        .map { Arrays.copyOfRange(it, 0, 32) to Arrays.copyOfRange(it, 32, 64) }
        .map { SignatureData(BigInteger(1, it.first), BigInteger(1, it.second), recoveryParam) }
        .first()

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

fun packCiphertext(vararg data: ByteArray): String =
        data.joinToString(DELIMITER) { Base64.encodeToString(it, Base64.NO_WRAP) }

fun unpackCiphertext(ciphertext: String): List<ByteArray> =
        ciphertext
                .split(DELIMITER)
                .map { Base64.decode(it, Base64.NO_WRAP) }

internal fun ECKeyPair.getUncompressedPublicKeyWithPrefix(): ByteArray {
    val pubBytes = this.publicKey.toBytesPadded(UportSigner.UNCOMPRESSED_PUBLIC_KEY_SIZE)
    pubBytes[0] = 0x04
    return pubBytes
}

fun BigInteger.keyToBase64(keySize: Int = PRIVATE_KEY_SIZE): String =
        Base64.encodeToString(this.toBytesPadded(keySize), Base64.DEFAULT or Base64.NO_WRAP)