package me.uport.signer.demo

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import com.uport.sdk.signer.UportHDSigner
import com.uport.sdk.signer.encryption.KeyProtection
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*
import org.walleth.khex.toHexString

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        mnemonicGo.setOnClickListener({ _ ->
            val phrase = mnemonicPhraseField.text.toString()
            UportHDSigner().importHDSeed(this, KeyProtection.Level.SIMPLE, phrase, { err, address, publicKey ->
                errorField.text = err.toString()
                publicKeyField.text = Base64.decode(publicKey, Base64.DEFAULT).toHexString()
                addressField.text = address
            })
        })
    }

}
