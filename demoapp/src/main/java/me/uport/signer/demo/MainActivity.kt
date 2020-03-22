package me.uport.signer.demo

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        createKeys.setOnClickListener {
            val intent = Intent(this, CreateKeysActivity::class.java)
            startActivity(intent)
        }

        useKeys.setOnClickListener {
            val intent = Intent(this, UseKeysActivity::class.java)
            startActivity(intent)
        }

        use_keyguard.setOnClickListener {
            val intent = Intent(this, PinGuardedKeyActivity::class.java)
            startActivity(intent)
        }

        use_fingerprints.setOnClickListener {
            val intent = Intent(this, FingerprintGuardedKeyActivity::class.java)
            startActivity(intent)
        }
    }
}
