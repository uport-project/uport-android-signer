package com.uport.sdk.signer.encryption

import android.content.Context
import android.os.Build

object KeyProtectionFactory {

    fun obtain(context: Context, level: KeyProtection.Level): KeyProtection {

        //FIXME: this needs more love; some checks need to be performed before attempting secure storage
        val store = when (level) {

            KeyProtection.Level.SINGLE_PROMPT -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    KeyguardAsymmetricProtection()
                } else {
                    SimpleAsymmetricProtection()
                }
            }

            KeyProtection.Level.PROMPT -> {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    if (KeyProtection.hasSetupFingerprint(context)) {
                        FingerprintAsymmetricProtection()
                    } else {
                        KeyguardAsymmetricProtection(1)
                    }
                } else {
                    SimpleAsymmetricProtection()
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