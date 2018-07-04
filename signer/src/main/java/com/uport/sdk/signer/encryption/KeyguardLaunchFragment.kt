package com.uport.sdk.signer.encryption

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context.KEYGUARD_SERVICE
import android.content.Intent
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v4.app.FragmentManager

class KeyguardLaunchFragment : Fragment() {

    private lateinit var keyguardManager: KeyguardManager
    private lateinit var callback: KeyguardCallback
    private lateinit var purpose: String

    override
    fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        retainInstance = true
        keyguardManager = context?.getSystemService(KEYGUARD_SERVICE) as KeyguardManager
    }

    override
    fun onStart() {
        super.onStart()

        val keyguardIntent = keyguardManager.createConfirmDeviceCredentialIntent("uPort", purpose)

        startActivityForResult(keyguardIntent, REQUEST_CODE_KEYGUARD)
    }

    private fun init(purpose: String, callback: KeyguardCallback) {
        this.callback = callback
        this.purpose = purpose
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CODE_KEYGUARD) {
            val result = resultCode == Activity.RESULT_OK
            callback.onKeyguardResult(result)
            dismiss()
        }
    }

    private fun dismiss() {
        fragmentManager?.beginTransaction()?.remove(this)?.commit()
    }

    interface KeyguardCallback {
        fun onKeyguardResult(unlocked: Boolean)
    }

    companion object {

        private const val TAG_KEYGUARD_FRAGMENT: String = "keyguard_fragment"
        private const val REQUEST_CODE_KEYGUARD: Int = 19867

        fun show(fragManager: FragmentManager, purpose: String, callback: KeyguardCallback) {

            //cleanup..
            val headlessFragment = fragManager.findFragmentByTag(TAG_KEYGUARD_FRAGMENT) as KeyguardLaunchFragment?
            if (headlessFragment != null) {
                fragManager.beginTransaction().remove(headlessFragment).commitAllowingStateLoss()
            }

            val fragment = KeyguardLaunchFragment()
            fragment.init(purpose, callback)
            fragManager.beginTransaction().add(fragment, TAG_KEYGUARD_FRAGMENT).commit()
        }


    }
}