package me.uport.signer.demo

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        createKeys.setOnClickListener({
            val createKeysIntent = Intent(this, CreateKeysActivity::class.java)
            startActivity(createKeysIntent)
        })

        useKeys.setOnClickListener({
            val useKeysIntent = Intent(this, UseKeysActivity::class.java)
            startActivity(useKeysIntent)
        })
    }

}
