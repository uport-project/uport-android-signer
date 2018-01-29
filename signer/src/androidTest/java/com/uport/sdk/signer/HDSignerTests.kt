package com.uport.sdk.signer

import android.support.test.rule.ActivityTestRule
import android.util.Base64
import com.uport.sdk.signer.encryption.KeyProtection
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.kethereum.bip32.generateKey
import org.kethereum.bip39.Mnemonic
import org.kethereum.extensions.hexToBigInteger
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.concurrent.CountDownLatch

class HDSignerTests {

    @Rule
    @JvmField
    val mActivityRule: ActivityTestRule<TestDummyActivity> = ActivityTestRule(TestDummyActivity::class.java)

    @Before
    fun setupProviders() {
        //FIXME: temporary workaround while issue #20 of kethereum is still open
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun testSeedCreationAndUsage() {
        val activity = mActivityRule.activity
        val latch = CountDownLatch(1)

        UportHDSigner().createHDSeed(activity, KeyProtection.Level.SIMPLE, { err, rootAddress, pubKey ->

            assertNull(err)

            assertTrue(rootAddress.matches("^0x[0-9a-fA-F]+$".toRegex()))

            val pubKeyBytes = Base64.decode(pubKey, Base64.DEFAULT)
            assertEquals(65, pubKeyBytes.size)

            UportHDSigner().signJwtBundle(activity, rootAddress, "m/0'", Base64.encodeToString("hello".toByteArray(), Base64.DEFAULT), "", { error, _ ->
                assertNull(error)
                latch.countDown()
            })
        })

        latch.await()
    }

    @Test
    fun testSeedImport() {
        val activity = mActivityRule.activity
        val referenceSeedPhrase = "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        val referenceAddress = "0x794adde0672914159c1b77dd06d047904fe96ac8"
        val referencePublicKey = "BFcWkA3uvBb9nSyJmk5rJgx69UtlGN0zwDiNx5TcVmENEUcvF2V26GYP9/3HNE/7vquemm45hDYEqr1/Nph9aIE="

        val latch = CountDownLatch(1)
        UportHDSigner().importHDSeed(activity, KeyProtection.Level.SIMPLE, referenceSeedPhrase, { err, address, pubKey ->

            assertNull(err)

            assertEquals(referenceAddress, address)

            assertEquals(referencePublicKey, pubKey)

            latch.countDown()
        })

        latch.await()
    }

    //JWT signing something using a derived uPort Root
    @Test
    fun testJwtComponents() {

        val referenceSeed = Mnemonic.mnemonicToSeed("vessel ladder alter error federal sibling chat ability sun glass valve picture")
        val referencePayload = "Hello, world!".toByteArray()

        val referencePrivateKey = "65fc670d9351cb87d1f56702fb56a7832ae2aab3427be944ab8c9f2a0ab87960".hexToBigInteger()

        val referenceR = "6bcd81446183af193ca4a172d5c5c26345903b24770d90b5d790f74a9dec1f68".hexToBigInteger()
        val referenceS = "e2b85b3c92c9b4f3cf58de46e7997d8efb6e14b2e532d13dfa22ee02f3a43d5d".hexToBigInteger()

        val derivedRootExtendedKey = generateKey(referenceSeed, UportHDSigner.UPORT_ROOT_DERIVATION_PATH)

        assertEquals(referencePrivateKey, derivedRootExtendedKey.getKeyPair().privateKey)

        val keyPair = derivedRootExtendedKey.getKeyPair()

        val sigData = UportSigner().signJwt(referencePayload, keyPair)

        assertEquals(referenceR, sigData.r)
        assertEquals(referenceS, sigData.s)
    }


    @Test
    fun testSeedImportAndUsage() {
        val activity = mActivityRule.activity
        val referenceSeedPhrase = "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        val referenceRootAddress = "0x794adde0672914159c1b77dd06d047904fe96ac8"
        val referenceSignature = "lnEso6Io2pJvlC6sWDLRkvxvpXqcUpZpvr4sdpHcTGA66Y1zher8KlrnWzQ2tt_lpxpx2YYdbfdtkfVmwjex2Q"
        val referencePayload = Base64.encodeToString("Hello world".toByteArray(), Base64.DEFAULT)

        ensureSeedIsImported(referenceSeedPhrase)

        val latch = CountDownLatch(1)

        UportHDSigner().signJwtBundle(activity, referenceRootAddress, UportHDSigner.UPORT_ROOT_DERIVATION_PATH, referencePayload, "", { error, signature ->
            assertNull(error)
            assertEquals(referenceSignature, signature)

            latch.countDown()
        })

        latch.await()

    }

    @Test
    fun checkShowSeed() {
        val activity = mActivityRule.activity
        val referenceSeedPhrase = "idle giraffe soldier dignity angle tiger false finish busy glow ramp frog"
        val referenceRootAddress = "0xd2bf228f4bf45a9a3d2247d27235e4c07ff0c275"

        ensureSeedIsImported(referenceSeedPhrase)

        //check that retrieving it yields the same phrase
        val latch = CountDownLatch(1)
        UportHDSigner().showHDSeed(activity, referenceRootAddress, "", { ex, phrase ->
            assertNull(ex)
            assertEquals(referenceSeedPhrase, phrase)
            latch.countDown()
        })
        latch.await()
    }

    @Test
    fun getPrivateKeyForPath() {

        val referenceSeedPhrase = "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        val referenceSeedAddress = "0x794adde0672914159c1b77dd06d047904fe96ac8"
        ensureSeedIsImported(referenceSeedPhrase)

        val referencePrivateKey = "ZfxnDZNRy4fR9WcC+1angyriqrNCe+lEq4yfKgq4eWA="
        UportHDSigner().getPrivateKeyForPath(
                mActivityRule.activity,
                referenceSeedAddress,
                UportHDSigner.UPORT_ROOT_DERIVATION_PATH,
                "",
                { err, encodedKey ->
                    assertNull(err)
                    assertEquals(referencePrivateKey, encodedKey)
                }
        )
    }

    private fun ensureSeedIsImported(phrase: String) {
        //ensure seed is imported
        val latch = CountDownLatch(1)
        UportHDSigner().importHDSeed(mActivityRule.activity, KeyProtection.Level.SIMPLE, phrase, { err, _, _ ->
            assertNull(err)
            latch.countDown()
        })
        latch.await()
    }

}