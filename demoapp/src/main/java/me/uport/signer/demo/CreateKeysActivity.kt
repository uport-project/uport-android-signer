package me.uport.signer.demo

import android.annotation.SuppressLint
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.uport.sdk.signer.UportHDSigner
import com.uport.sdk.signer.encryption.KeyProtection
import kotlinx.android.synthetic.main.activity_create_keys.*
import kotlinx.android.synthetic.main.content_create_keys.*
import me.uport.sdk.core.decodeBase64
import org.kethereum.bip39.generateMnemonic
import org.kethereum.bip39.wordlists.WORDLIST_ENGLISH
import org.komputing.khex.extensions.toHexString


class CreateKeysActivity : AppCompatActivity() {

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_keys)
        setSupportActionBar(toolbar)

        generateButton.setOnClickListener {
            val phrase = generateMnemonic(wordList = WORDLIST_ENGLISH)
            mnemonicPhraseField.setText(phrase)
        }

        importButton.setOnClickListener { view ->
            val phrase = mnemonicPhraseField.text.toString()
            UportHDSigner().importHDSeed(view.context, KeyProtection.Level.SIMPLE, phrase) { err, address, publicKey ->
                errorField.text = "error: ${err.toString()}"
                publicKeyField.text = "publicKey: ${publicKey.decodeBase64().toHexString()}"
                addressField.text = "address: $address"
            }
        }

    }

}
