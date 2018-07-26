package com.uport.sdk.signer

import android.support.test.InstrumentationRegistry
import android.util.Base64
import com.uport.sdk.signer.UportSigner.Companion.ERR_ACTIVITY_DOES_NOT_EXIST
import com.uport.sdk.signer.encryption.KeyProtection
import com.uport.sdk.signer.testutil.ensureKeyIsImportedInTargetContext
import com.uport.sdk.signer.testutil.ensureSeedIsImportedInTargetContext
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kethereum.bip39.Mnemonic
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch

class UserInteractionContextTests {

    private val phrase = Mnemonic.generateMnemonic()
    private val key = ByteArray(32).apply { SecureRandom().nextBytes(this) }

    private val context = InstrumentationRegistry.getTargetContext()
    //import a key that needs user authentication
    private val seedHandle = ensureSeedIsImportedInTargetContext(phrase, KeyProtection.Level.PROMPT)
    private val keyHandle = ensureKeyIsImportedInTargetContext(key, KeyProtection.Level.PROMPT)

    @Test
    fun shouldThrowOnShowSeedWhenUsingActivityDependentKey() {

        val latch = CountDownLatch(1)
        UportHDSigner().showHDSeed(context, seedHandle, "this is shown to the user") { err, _ ->

            assertNotNull(err!!)
            assertTrue(err.message?.contains(ERR_ACTIVITY_DOES_NOT_EXIST) ?: false)

            latch.countDown()
        }

        latch.await()
    }

    @Test
    fun shouldThrowOnSignJwtWhenUsingActivityDependentKey() {

        val somePayloadData = "payload to be signed".toByteArray()
        val payload = Base64.encodeToString(somePayloadData, Base64.NO_WRAP)

        val latch = CountDownLatch(1)
        UportHDSigner().signJwtBundle(context, seedHandle, UportHDSigner.UPORT_ROOT_DERIVATION_PATH, payload, "this is shown to the user") { err, _ ->

            assertNotNull(err!!)
            assertTrue(err.message?.contains(ERR_ACTIVITY_DOES_NOT_EXIST) ?: false)

            latch.countDown()
        }

        latch.await()
    }

    @Test
    fun shouldThrowOnSignTxWhenUsingActivityDependentKey() {

        val somePayloadData = "payload to be signed".toByteArray()
        val payload = Base64.encodeToString(somePayloadData, Base64.NO_WRAP)

        val latch = CountDownLatch(1)
        UportHDSigner().signTransaction(context, seedHandle, UportHDSigner.UPORT_ROOT_DERIVATION_PATH, payload, "this is shown to the user") { err, _ ->

            assertNotNull(err!!)
            assertTrue(err.message?.contains(ERR_ACTIVITY_DOES_NOT_EXIST) ?: false)

            latch.countDown()
        }

        latch.await()
    }


    @Test
    fun shouldThrowOnSignJwtSimpleWhenUsingActivityDependentKey() {

        val somePayloadData = "payload to be signed".toByteArray()
        val payload = Base64.encodeToString(somePayloadData, Base64.NO_WRAP)

        val latch = CountDownLatch(1)
        UportSigner().signJwtBundle(context, keyHandle, payload, "this is shown to the user") { err, _ ->

            assertNotNull(err!!)
            assertTrue(err.message?.contains(ERR_ACTIVITY_DOES_NOT_EXIST) ?: false)

            latch.countDown()
        }

        latch.await()
    }

    @Test
    fun shouldThrowOnSignTxSimpleWhenUsingActivityDependentKey() {

        val somePayloadData = "payload to be signed".toByteArray()
        val payload = Base64.encodeToString(somePayloadData, Base64.NO_WRAP)

        val latch = CountDownLatch(1)
        UportSigner().signTransaction(context, keyHandle, payload, "this is shown to the user") { err, _ ->

            assertNotNull(err!!)
            assertTrue(err.message?.contains(ERR_ACTIVITY_DOES_NOT_EXIST) ?: false)

            latch.countDown()
        }

        latch.await()
    }

}