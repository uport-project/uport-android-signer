package me.uport.signer.demo

import android.content.Context
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView


class KeyPairAdapter(context: Context, data: List<String>) : RecyclerView.Adapter<KeyPairAdapter.ViewHolder>() {

    private val keyPairs: MutableList<String> = listOf("").toMutableList()
    private val mInflater: LayoutInflater = LayoutInflater.from(context)
    private var mClickListener: ItemClickListener? = null

    init {
        keyPairs.clear()
        keyPairs.addAll(data)
    }

    // inflates the row layout from xml when needed
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = mInflater.inflate(R.layout.key_pair_item, parent, false)
        return ViewHolder(view)
    }

    // binds the data to the textview in each row
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val keyPair = keyPairs[position]
        holder.myTextView.text = keyPair
    }

    // total number of rows
    override fun getItemCount(): Int {
        return keyPairs.size
    }


    // stores and recycles views as they are scrolled off screen
    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView), View.OnClickListener {

        var myTextView: TextView = itemView.findViewById(R.id.key_pair_item_text_field)

        init {
            itemView.setOnClickListener(this)
        }

        override fun onClick(view: View) {
            if (mClickListener != null) mClickListener!!.onItemClick(view, adapterPosition)
        }
    }

    // convenience method for getting data at click position
    fun getItem(id: Int): String {
        return keyPairs[id]
    }

    // allows clicks events to be caught
    fun setClickListener(itemClickListener: ItemClickListener) {
        this.mClickListener = itemClickListener
    }

    // parent activity will implement this method to respond to click events
    interface ItemClickListener {
        fun onItemClick(view: View, position: Int)
    }
}