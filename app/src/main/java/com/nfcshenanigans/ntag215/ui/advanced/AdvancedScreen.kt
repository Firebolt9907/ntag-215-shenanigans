package com.nfcshenanigans.ntag215.ui.advanced

import android.os.Build
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.nfcshenanigans.ntag215.core.Ascii
import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.data.NfcAvailability
import com.nfcshenanigans.ntag215.nfc.MemoryDump
import com.nfcshenanigans.ntag215.nfc.PageStatus
import com.nfcshenanigans.ntag215.ui.common.InfoRow
import com.nfcshenanigans.ntag215.ui.common.MaskableField
import com.nfcshenanigans.ntag215.ui.common.MessageCard
import com.nfcshenanigans.ntag215.ui.common.MessageKind
import com.nfcshenanigans.ntag215.ui.common.NfcStatusBanner
import com.nfcshenanigans.ntag215.ui.common.ScanPrompt
import com.nfcshenanigans.ntag215.ui.common.SectionCard
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun AdvancedScreen(vm: AdvancedViewModel, nfc: NfcAvailability, onOpenNfcSettings: () -> Unit) {
    val s by vm.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        NfcStatusBanner(nfc, onOpenNfcSettings)
        when {
            s.busy -> ScanPrompt("Reading memory… keep the tag still", busy = true)
            s.armed == ArmedAction.AUTH_DUMP -> ScanPrompt("Hold the tag to authenticate and read all pages")
            s.armed == ArmedAction.REMOVE_PROTECTION -> ScanPrompt("Hold the tag to remove password protection")
            else -> ScanPrompt("Hold a tag to read every accessible page")
        }
        s.error?.let { MessageCard(it, MessageKind.ERROR) }
        s.info?.let { MessageCard(it, MessageKind.INFO) }

        SectionCard("Authentication", icon = Icons.Filled.Lock) {
            MaskableField(s.password, vm::onPassword, "Password (8 hex digits)", error = s.passwordError, capitalization = KeyboardCapitalization.Characters)
            OutlinedTextField(
                value = s.pack,
                onValueChange = vm::onPack,
                label = { Text("Expected PACK (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::authenticateAndDump, enabled = !s.busy) { Text("Authenticate & read") }
                if (s.armed != ArmedAction.NONE) TextButton(onClick = vm::disarm) { Text("Cancel") }
            }
            OutlinedButton(onClick = vm::askRemove, enabled = !s.busy) { Text("Remove password protection…") }
        }

        s.dump?.let { DumpContent(it, s, vm) }
        Diagnostics(s, nfc)

        SectionCard("Command log", icon = Icons.AutoMirrored.Filled.List) {
            Text("Commands and outcomes only. Data, passwords and secrets are never logged.", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = vm::refreshLog) { Text("Refresh") }
                TextButton(onClick = vm::clearLog) { Text("Clear") }
            }
            val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
            s.log.forEach { e ->
                Text(
                    "${fmt.format(Date(e.timestampMs))}  ${e.command}  → ${e.outcome}" + if (e.durationMs > 0) " (${e.durationMs} ms)" else "",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                )
            }
        }
    }

    if (s.confirmRemove) {
        AlertDialog(
            onDismissRequest = vm::dismissRemove,
            title = { Text("Remove password protection?") },
            text = {
                Text(
                    "This sets AUTH0 = FFh and PROT = 0 after authenticating once with the password above. " +
                        "Private ID and secret will become readable by any NFC app. This is reversible: write the tag again to re-enable protection. " +
                        "Lock bits and other configuration bits are not changed.",
                )
            },
            confirmButton = { TextButton(onClick = vm::confirmRemove) { Text("Remove protection") } },
            dismissButton = { TextButton(onClick = vm::dismissRemove) { Text("Cancel") } },
        )
    }
}

@Composable
private fun DumpContent(d: MemoryDump, s: AdvancedUiState, vm: AdvancedViewModel) {
    SectionCard("Protection configuration", icon = Icons.Filled.Settings) {
        InfoRow("UID", d.identity.uidDisplay, monospace = true)
        InfoRow("GET_VERSION", d.identity.version.raw.toHex(" "), monospace = true)
        InfoRow("Product", "${d.identity.version.productName}, storage ${d.identity.version.storageDescription}")
        InfoRow("Authentication", if (d.authenticated) "Authenticated" + (d.packHex?.let { ", PACK $it" } ?: "") else (d.authError ?: "Not authenticated"))
        InfoRow("Protection", d.protection.summary())
        d.identity.cc?.let { cc ->
            InfoRow("CC (page 0x03)", "$cc · magic ${if (cc.hasNdefMagic) "OK" else "missing"} · v${cc.versionMajor}.${cc.versionMinor} · ${cc.dataAreaBytes} B · access 0x${Hex.byte(cc.access)}")
        }
        d.identity.staticLock?.let { l ->
            InfoRow("Static lock", "0x${Hex.byte(l.lock0)} 0x${Hex.byte(l.lock1)} · locked pages: ${l.lockedPages.sorted().joinToString { "0x" + Hex.byte(it) }.ifEmpty { "none" }}")
        }
        d.dynamicLock?.let { l ->
            InfoRow("Dynamic lock", "0x${Hex.byte(l.lock0)} 0x${Hex.byte(l.lock1)} 0x${Hex.byte(l.lock2)} · ${if (l.anySet) "lock bits set" else "no locks"}")
        } ?: InfoRow("Dynamic lock", "Protected (authenticate to read)")
        d.config?.let { c ->
            InfoRow("CFG0 (0x83)", c.cfg0.toHex(" "), monospace = true)
            InfoRow("CFG1 (0x84)", c.cfg1.toHex(" "), monospace = true)
            InfoRow("AUTH0", "0x${Hex.byte(c.auth0)}" + if (c.protectionActive) "" else " (protection disabled)")
            InfoRow("PROT", if (c.prot) "1 (read + write protected)" else "0 (write protected only)")
            InfoRow("CFGLCK", if (c.cfgLock) "1 (configuration permanently locked)" else "0")
            InfoRow("AUTHLIM", c.describeAuthLim())
            InfoRow("NFC counter", "enabled=${c.nfcCounterEnabled}, password protected=${c.nfcCounterPasswordProtected}")
            InfoRow("ASCII mirror", if (c.mirrorEnabled) "conf ${c.mirrorConf}, page 0x${Hex.byte(c.mirrorPage)}, byte ${c.mirrorByte}" else "disabled")
            InfoRow("Strong modulation", c.strongModulation.toString())
        } ?: InfoRow("CFG0/CFG1", "Protected (authenticate to read)")
    }

    SectionCard("Memory (${Ntag215Memory.TOTAL_PAGES} pages)", icon = Icons.Filled.Build) {
        val privateReadable = d.pages[Ntag215Memory.PRIVATE_ID_PAGE].status == PageStatus.READ
        if (privateReadable) {
            TextButton(onClick = vm::toggleReveal) { Text(if (s.revealPrivate) "Mask private pages" else "Reveal private pages 0x20-0x28") }
        }
        Text("Page │ Hex         │ ASCII │ Purpose", fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.horizontalScroll(rememberScrollState())) {
            d.pages.forEach { p ->
                val isPrivate = p.page in Ntag215Memory.PRIVATE_FIRST_PAGE..Ntag215Memory.PRIVATE_LAST_PAGE
                val (hex, ascii) = when {
                    p.status == PageStatus.PROTECTED -> "-- -- -- --" to "🔒   "
                    isPrivate && !s.revealPrivate -> "•• •• •• ••" to "••••"
                    else -> p.data!!.toHex(" ") to Ascii.display(p.data)
                }
                Text(
                    "0x${Hex.byte(p.page)} │ $hex │ $ascii  │ ${p.name}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = if (p.status == PageStatus.PROTECTED) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                )
            }
        }
        Text("PWD and PACK always read as 00 (datasheet 8.8.1).", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun Diagnostics(s: AdvancedUiState, nfc: NfcAvailability) {
    SectionCard("Diagnostics", icon = Icons.Filled.Info) {
        InfoRow("Device", "${Build.MANUFACTURER} ${Build.MODEL}")
        InfoRow("Android", "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        InfoRow("NFC", nfc.name.lowercase())
        s.tech?.let {
            InfoRow("Technologies", it.techs.joinToString())
            InfoRow("ATQA / SAK", "${it.atqa ?: "?"} / ${it.sak ?: "?"}", monospace = true)
        }
        s.dump?.let {
            InfoRow("Max transceive", "${it.maxTransceiveLength} bytes")
            InfoRow("FAST_READ", if (it.fastReadUsed) "supported" else "fell back to READ")
        }
    }
}
