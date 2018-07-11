package me.uport.signer.demo

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import com.uport.sdk.signer.UportHDSigner
import com.uport.sdk.signer.encryption.KeyProtection
import kotlinx.android.synthetic.main.activity_pin_guarded_key.*
import java.util.*

class PinGuardedKeyActivity : AppCompatActivity() {

    private var hdSeedHandle: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pin_guarded_key)

        var hardwareStatusText = ""
        UportHDSigner().hasSecuredKeyguard(this) {
            hardwareStatusText += "\nsecure keyguard: $it"
            hardware_status.text = hardwareStatusText
        }

        createKeyBtn.setOnClickListener {
            UportHDSigner().createHDSeed(this, KeyProtection.Level.SINGLE_PROMPT) { err, address, publicKey ->

                if (err != null) {
                    key_status.text = err.message
                    return@createHDSeed
                }
                key_status.text = "key created: $address"
                hdSeedHandle = address
            }
        }

        signBtn.setOnClickListener {

            //random payload to be signed
            val msgBytes = ByteArray(3139).also { Random().nextBytes(it) }

            //needs to be wrapped as a base64 string
            val b64Payload = Base64.encodeToString(msgBytes, Base64.NO_WRAP)

            UportHDSigner().signTransaction(
                    this,
                    hdSeedHandle,
                    "m/44'/60'/0'/0/0",
                    b64Payload,
                    "${getString(R.string.app_name)} is requesting your approval to sign a random string of bits with a newly minted key"
            ) { err, sigData ->
                if (err == null) {
                    sign_result.text = "success : $sigData"
                } else {
                    sign_result.text = "error: $err\n caused by: ${err.cause}"
                }
            }
        }



    }
}
