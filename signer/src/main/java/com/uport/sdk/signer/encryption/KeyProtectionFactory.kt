package com.uport.sdk.signer.encryption

import android.content.Context

object KeyProtectionFactory {

    fun obtain(context: Context, level: KeyProtection.Level): KeyProtection {

        //FIXME: this needs more love; some checks need to be performed before attempting secure storage
        val store = when (level) {

            KeyProtection.Level.SINGLE_PROMPT -> {
                KeyguardAsymmetricProtection()
            }

            KeyProtection.Level.PROMPT -> {

                if (KeyProtection.hasSetupFingerprint(context)) {
                    FingerprintAsymmetricProtection()
                } else {
                    val sessionTime = if (KeyProtection.hasFingerprintHardware(context)) {
                        0 // pop keyguard with 0 second authentication window (practically for every use)

                        /**
                         * reason for this behavior:
                         *
                         * on devices that have fingerprint hardware but haven't setup fingerprints
                         * an IllegalBlockSizeException is thrown if the requested session time is "-1"
                         * with the cause being KeyStoreException("Key user not authenticated")
                         *
                         * Therefore, we emulate this by a 0 second authentication window
                         */
                    } else {
                        -1 // pop keyguard for every use
                    }
                    KeyguardAsymmetricProtection(sessionTime)
                }
            }

            KeyProtection.Level.SIMPLE -> {
                SimpleAsymmetricProtection()
            }

            else -> {
                SimpleAsymmetricProtection()
            }
        }
        //ensure store is setup
        store.genKey(context)
        return store
    }

}