package me.uport.signer.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import android.view.View
import android.widget.Toast
import com.uport.sdk.signer.UportHDSigner
import kotlinx.android.synthetic.main.activity_use_keys.*

class UseKeysActivity : AppCompatActivity(), KeyPairAdapter.ItemClickListener {

    private lateinit var adapter: KeyPairAdapter

    override fun onItemClick(view: View, position: Int) {
        Toast.makeText(
            this,
            "you clicked ${adapter.getItem(position)} on row number $position",
            Toast.LENGTH_SHORT
        ).show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_use_keys)

        val keyPairs = UportHDSigner().allHDRoots(this)

        // set up the RecyclerView
        recycler_view.layoutManager =
            LinearLayoutManager(this)
        adapter = KeyPairAdapter(this, keyPairs)
        adapter.setClickListener(this)
        recycler_view.adapter = adapter

        val dividerItemDecoration =
            DividerItemDecoration(
                recycler_view.context,
                (recycler_view.layoutManager as LinearLayoutManager).orientation
            )
        recycler_view.addItemDecoration(dividerItemDecoration)
    }
}
