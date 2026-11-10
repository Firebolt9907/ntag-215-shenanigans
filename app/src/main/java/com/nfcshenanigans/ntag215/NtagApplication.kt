package com.nfcshenanigans.ntag215

import android.app.Application
import com.nfcshenanigans.ntag215.data.Ntag215Repository

class NtagApplication : Application() {
    val repository: Ntag215Repository by lazy { Ntag215Repository() }
}
