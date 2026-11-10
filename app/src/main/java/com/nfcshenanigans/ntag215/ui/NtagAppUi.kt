package com.nfcshenanigans.ntag215.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.nfcshenanigans.ntag215.data.AppScreen
import com.nfcshenanigans.ntag215.data.Ntag215Repository
import com.nfcshenanigans.ntag215.ui.advanced.AdvancedScreen
import com.nfcshenanigans.ntag215.ui.advanced.AdvancedViewModel
import com.nfcshenanigans.ntag215.ui.read.ReadScreen
import com.nfcshenanigans.ntag215.ui.read.ReadViewModel
import com.nfcshenanigans.ntag215.ui.write.WriteScreen
import com.nfcshenanigans.ntag215.ui.write.WriteViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NtagAppUi(repository: Ntag215Repository, onOpenNfcSettings: () -> Unit) {
    val factory = viewModelFactory {
        initializer { ReadViewModel(repository) }
        initializer { WriteViewModel(repository) }
        initializer { AdvancedViewModel(repository) }
    }
    val readVm: ReadViewModel = viewModel(factory = factory)
    val writeVm: WriteViewModel = viewModel(factory = factory)
    val advancedVm: AdvancedViewModel = viewModel(factory = factory)

    var screen by rememberSaveable { mutableStateOf(AppScreen.READ) }
    LaunchedEffect(screen) { repository.setActiveScreen(screen) }
    val nfc by repository.nfcAvailability.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        when (screen) {
                            AppScreen.READ -> "Read Tag"
                            AppScreen.WRITE -> "Write Tag"
                            AppScreen.ADVANCED -> "Advanced"
                        },
                    )
                },
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(screen == AppScreen.READ, { screen = AppScreen.READ }, { Icon(Icons.Filled.Search, null) }, label = { Text("Read") })
                NavigationBarItem(screen == AppScreen.WRITE, { screen = AppScreen.WRITE }, { Icon(Icons.Filled.Edit, null) }, label = { Text("Write") })
                NavigationBarItem(screen == AppScreen.ADVANCED, { screen = AppScreen.ADVANCED }, { Icon(Icons.Filled.Build, null) }, label = { Text("Advanced") })
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (screen) {
                AppScreen.READ -> ReadScreen(readVm, nfc, onOpenNfcSettings)
                AppScreen.WRITE -> WriteScreen(writeVm, nfc, onOpenNfcSettings)
                AppScreen.ADVANCED -> AdvancedScreen(advancedVm, nfc, onOpenNfcSettings)
            }
        }
    }
}
