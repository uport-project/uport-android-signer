package me.uport.signer.demo

import android.annotation.SuppressLint
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.widget.Toast
import com.uport.sdk.signer.UportHDSigner
import com.uport.sdk.signer.encryption.KeyProtection
import kotlinx.android.synthetic.main.activity_create_keys.*
import kotlinx.android.synthetic.main.activity_pin_guarded_key.*
import kotlinx.android.synthetic.main.content_create_keys.*
import me.uport.sdk.core.decodeBase64
import org.kethereum.bip39.generateMnemonic
import org.kethereum.bip39.wordlists.WORDLIST_ENGLISH
import org.walleth.khex.toHexString


class CreateKeysActivity : AppCompatActivity() {

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_keys)
        setSupportActionBar(toolbar)

        var hardwareStatusText = ""
        UportHDSigner().hasSecuredKeyguard(this) {
            hardwareStatusText += "\nsecure keyguard: $it"
        }
        UportHDSigner().hasFingerprintHardware(this) {
            hardwareStatusText += "\nfingerprint hardware: $it"
        }
        UportHDSigner().hasSetupFingerprints(this) {
            hardwareStatusText += "\nfingerprints enrolled: $it"
        }

        errorField.text = hardwareStatusText

        generateButton.setOnClickListener {
            val phrase = generateMnemonic(wordList = WORDLIST_ENGLISH)
            mnemonicPhraseField.setText(phrase)
        }

        importButton.setOnClickListener { _ ->
            val phrase = mnemonicPhraseField.text.toString()
            val selectedOption = keyProtectionOptions.checkedRadioButtonId

            val protection: KeyProtection.Level = when(selectedOption) {
                R.id.keyguard -> KeyProtection.Level.SINGLE_PROMPT
                R.id.fingerprint -> KeyProtection.Level.PROMPT
                else -> KeyProtection.Level.SIMPLE
            }

            UportHDSigner().importHDSeed(this, protection, phrase) { err, address, publicKey ->
                errorField.text = "error: ${err.toString()}"
                publicKeyField.text = "publicKey: ${publicKey.decodeBase64().toHexString()}"
                addressField.text = "address: $address"
            }
        }
    }
}
