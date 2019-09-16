package com.uport.sdk.signer.crypto.bip32

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.kethereum.bip32.generateChildKey
import org.kethereum.bip32.model.Seed
import org.kethereum.bip32.toExtendedKey
import org.kethereum.bip44.BIP44Element
import org.komputing.khex.extensions.hexToByteArray
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.Security

class ExtendedKeyTest {

    @Before
    fun setupProviders() {
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun createPrivateFromSeed() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        val expectedExtendedPrivateKey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        val key = Seed(seed).toExtendedKey()
        val encoded = key.serialize()
        assertEquals(expectedExtendedPrivateKey, encoded)
    }

    @Test
    fun createPublicFromSeed() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        val expectedExtendedPublicKey = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        val key = Seed(seed).toExtendedKey(true)
        val encoded = key.serialize(publicKeyOnly = true)
        assertEquals(expectedExtendedPublicKey, encoded)
    }

    @Test
    fun createNonHardenedChildPrivateKey() {
        val seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".hexToByteArray()
        val expectedExtendedPrivateKey = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        val key = Seed(seed).toExtendedKey()

        val child = key.generateChildKey(BIP44Element(false, 0))
        val encoded = child.serialize()
        assertEquals(expectedExtendedPrivateKey, encoded)
    }

    @Test
    fun `derive non hardened public vs private`() {
        val seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".hexToByteArray()
        val expectedExtendedPublicKey = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        val extendedPriv = Seed(seed).toExtendedKey()
        val extendedPub = Seed(seed).toExtendedKey(publicKeyOnly = true)

        val childPriv = extendedPriv.generateChildKey(BIP44Element(false, 0))
        val childPub = extendedPub.generateChildKey(BIP44Element(false, 0))

        val encodedPriv = childPriv.serialize(publicKeyOnly = true)
        val encodedPub = childPub.serialize(publicKeyOnly = true)

        assertEquals(encodedPub, encodedPriv)
        assertEquals(expectedExtendedPublicKey, encodedPub)
    }

    @Test
    fun createNonHardenedChildPublicKey() {
        //Chain m/0
        val seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".hexToByteArray()
        val expectedExtendedPublicKey = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        val key = Seed(seed).toExtendedKey(true)

        val child = key.generateChildKey(BIP44Element(false, 0))
        val encoded = child.serialize(publicKeyOnly = true)
        assertEquals(expectedExtendedPublicKey, encoded)
    }

    @Test
    fun createPrivateChildFromHardenedPath() {
        //Chain m/0/2147483647'

        val seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".hexToByteArray()
        val expectedExtendedPrivateKey = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"

        val master = Seed(seed).toExtendedKey()

        val child1 = master.generateChildKey(BIP44Element(false, 0))
        val child2 = child1.generateChildKey(BIP44Element(true, 2147483647))

        val result = child2.serialize()
        assertEquals(expectedExtendedPrivateKey, result)

    }

    @Test
    fun createPublicChildFromHardenedPath() {
        //Chain m/0/2147483647'

        //because it's a hardened path, we have to derive the private child and serialize only the public part

        val seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".hexToByteArray()
        val expectedExtendedPublicKey = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"

        val master = Seed(seed).toExtendedKey()

        val child1 = master.generateChildKey(BIP44Element(false, 0))
        val child2 = child1.generateChildKey(BIP44Element(true, 2147483647))

        val result = child2.serialize(true)
        assertEquals(expectedExtendedPublicKey, result)

    }

    @Test(expected = IllegalArgumentException::class)
    fun failWhenDerivingPublicChildFromPublicHardened() {

        //Chain m/2147483647'
        // hardened paths don't allow derivation starting from public keys
        val masterPub = Seed("whatever".toByteArray()).toExtendedKey(true)

        //expect crash
        masterPub.generateChildKey(BIP44Element(true, 2147483647))
    }

    @Test
    fun bufferEndianness() {

        val payloadArray: ByteArray = byteArrayOf(0, 1, 2, 3, 4)
        val seqNum = 0x00ABCDEF

        val destinationSimple = ByteArray(payloadArray.size + 4)
        val destinationBuffer = ByteBuffer.allocate(payloadArray.size + 4)

        System.arraycopy(payloadArray, 0, destinationSimple, 0, payloadArray.size)
        destinationSimple[payloadArray.size] = (seqNum.ushr(24) and 0xff).toByte()
        destinationSimple[payloadArray.size + 1] = (seqNum.ushr(16) and 0xff).toByte()
        destinationSimple[payloadArray.size + 2] = (seqNum.ushr(8) and 0xff).toByte()
        destinationSimple[payloadArray.size + 3] = (seqNum and 0xff).toByte()

        destinationBuffer.order(ByteOrder.BIG_ENDIAN)
        val destBuffArray = destinationBuffer
                .put(payloadArray)
                .putInt(seqNum)
                .array()

        assertArrayEquals(destBuffArray, destinationSimple)
    }

}
