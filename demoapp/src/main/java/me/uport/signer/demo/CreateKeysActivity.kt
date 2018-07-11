package me.uport.signer.demo

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import com.uport.sdk.signer.UportHDSigner
import com.uport.sdk.signer.encryption.KeyProtection
import kotlinx.android.synthetic.main.activity_create_keys.*
import kotlinx.android.synthetic.main.content_create_keys.*
import org.kethereum.bip39.Mnemonic
import org.walleth.khex.toHexString


class CreateKeysActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_keys)
        setSupportActionBar(toolbar)

        generateButton.setOnClickListener {
            val phrase = Mnemonic.generateMnemonic()
            mnemonicPhraseField.setText(phrase)
        }

        importButton.setOnClickListener { _ ->
            val phrase = mnemonicPhraseField.text.toString()
            UportHDSigner().importHDSeed(this, KeyProtection.Level.SIMPLE, phrase) { err, address, publicKey ->
                errorField.text = "error: ${err.toString()}"
                publicKeyField.text = "publicKey: ${Base64.decode(publicKey, Base64.DEFAULT).toHexString()}"
                addressField.text = "address: $address"
            }
        }

    }

}
