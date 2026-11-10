package com.nfcshenanigans.ntag215

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.nfcshenanigans.ntag215.data.AppScreen
import com.nfcshenanigans.ntag215.data.NfcAvailability
import com.nfcshenanigans.ntag215.ui.NtagAppUi
import com.nfcshenanigans.ntag215.ui.theme.NtagTheme
import kotlinx.coroutines.launch

/**
 * Hosts the Compose UI and owns NFC reader mode. Reader mode is enabled only while resumed, so tags
 * are delivered to this app (not dispatched to other apps) while it is in the foreground.
 */
class MainActivity : ComponentActivity(), NfcAdapter.ReaderCallback {

    private var adapter: NfcAdapter? = null
    private val repository by lazy { (application as NtagApplication).repository }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            refreshNfcState()
            if (isResumed()) enableReaderMode(repository.activeScreen.value)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        adapter = NfcAdapter.getDefaultAdapter(this)
        refreshNfcState()
        setContent {
            NtagTheme {
                NtagAppUi(
                    repository = repository,
                    onOpenNfcSettings = { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) },
                )
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                repository.activeScreen.collect { enableReaderMode(it) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshNfcState()
        ContextCompat.registerReceiver(
            this, stateReceiver, IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(stateReceiver) }
        runCatching { adapter?.disableReaderMode(this) }
    }

    private fun isResumed() = lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)

    private fun refreshNfcState() {
        val a = adapter
        repository.setNfcAvailability(
            when {
                a == null -> NfcAvailability.UNSUPPORTED
                a.isEnabled -> NfcAvailability.ENABLED
                else -> NfcAvailability.DISABLED
            },
        )
    }

    private fun enableReaderMode(screen: AppScreen) {
        val a = adapter ?: return
        if (!a.isEnabled) return
        // The Read screen keeps Android's NDEF check enabled so it can report what ordinary
        // background scanning detects. Write/Advanced skip it for faster raw access.
        var flags = NfcAdapter.FLAG_READER_NFC_A
        if (screen != AppScreen.READ) flags = flags or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000) }
        runCatching { a.enableReaderMode(this, this, flags, extras) }
    }

    override fun onTagDiscovered(tag: Tag) {
        repository.onTagDiscovered(tag)
    }
}
