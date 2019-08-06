package com.uport.sdk.signer.encryption

import android.content.Context
import android.os.Build
import android.os.Build.VERSION_CODES.LOLLIPOP

/**
 * Exposes a method of obtaining a [KeyProtection] implementation based on a required level
 */
object KeyProtectionFactory {

    /**
     * returns a [KeyProtection] implementation based on the provided [level]
     *
     * The method requires an Application [context] that will be used to determine device security
     * capabilities and to initialize key stores when needed.
     */
    @Suppress("ComplexMethod")
    fun obtain(context: Context, level: KeyProtection.Level): KeyProtection {

        @Suppress("MoveVariableDeclarationIntoWhen")
        val apiAdjustedLevel = if (Build.VERSION.SDK_INT >= LOLLIPOP) {
            level
        } else {
            //only simple protection is available for KitKat
            KeyProtection.Level.SIMPLE
        }

        val store = when (apiAdjustedLevel) {

            KeyProtection.Level.SINGLE_PROMPT -> {
                KeyguardAsymmetricProtection()
            }

            KeyProtection.Level.PROMPT -> {

                if (KeyProtection.hasSetupFingerprint(context)) {
                    FingerprintAsymmetricProtection()
                } else {

                    // pop keyguard with 0 second authentication window (practically for every use)
                    val sessionTime = 0

                        /**
                         * reason for this behavior:
                         *
                         * On devices that have fingerprint hardware but haven't setup fingerprints
                         * an IllegalBlockSizeException is thrown if the requested session time is "-1"
                         * with the cause being KeyStoreException("Key user not authenticated")
                         *
                         * Also, on some devices that DO NOT HAVE fingerprint hardware, using a "-1"
                         * session time would throw
                         *  > java.lang.IllegalStateException: At least one fingerprint must be enrolled
                         *  > to create keys requiring user authentication for every use"
                         *
                         * Therefore, we emulate this by a 0 second authentication window
                         */

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