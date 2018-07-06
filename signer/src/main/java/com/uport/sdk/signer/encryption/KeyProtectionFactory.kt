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
                    KeyguardAsymmetricProtection(-1)
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