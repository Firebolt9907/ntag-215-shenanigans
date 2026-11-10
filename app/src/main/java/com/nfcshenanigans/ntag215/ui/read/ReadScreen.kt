package com.nfcshenanigans.ntag215.ui.read

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.nfcshenanigans.ntag215.core.Hex
import com.nfcshenanigans.ntag215.core.Ntag215Memory
import com.nfcshenanigans.ntag215.core.PrivateId
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.core.toHex
import com.nfcshenanigans.ntag215.data.NfcAvailability
import com.nfcshenanigans.ntag215.nfc.PrivateArea
import com.nfcshenanigans.ntag215.nfc.PrivateState
import com.nfcshenanigans.ntag215.nfc.TagReport
import com.nfcshenanigans.ntag215.ui.common.InfoRow
import com.nfcshenanigans.ntag215.ui.common.MaskableField
import com.nfcshenanigans.ntag215.ui.common.MessageCard
import com.nfcshenanigans.ntag215.ui.common.MessageKind
import com.nfcshenanigans.ntag215.ui.common.NfcStatusBanner
import com.nfcshenanigans.ntag215.ui.common.ScanPrompt
import com.nfcshenanigans.ntag215.ui.common.SecretValue
import com.nfcshenanigans.ntag215.ui.common.SectionCard
import com.nfcshenanigans.ntag215.ui.common.copyToClipboard

@Composable
fun ReadScreen(vm: ReadViewModel, nfc: NfcAvailability, onOpenNfcSettings: () -> Unit) {
    val s by vm.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        NfcStatusBanner(nfc, onOpenNfcSettings)
        PasswordCard(s, vm)
        when {
            s.busy -> ScanPrompt("Reading tag… keep it still", busy = true)
            s.awaitingAuthTap -> ScanPrompt(s.info ?: "Hold the tag to the phone to authenticate")
            s.report == null -> ScanPrompt("Hold an NTAG215 tag to the back of your phone")
            else -> ScanPrompt("Scan another tag at any time")
        }
        s.error?.let { MessageCard(it, MessageKind.ERROR) }
        if (!s.awaitingAuthTap) s.info?.let { MessageCard(it, MessageKind.INFO) }
        s.report?.let { ReportContent(it, s, vm) }
    }

    s.retryConfirmFailures?.let { failures ->
        AlertDialog(
            onDismissRequest = vm::dismissRetryDialog,
            title = { Text("Try another password?") },
            text = {
                Text(
                    "$failures failed attempt(s) on this tag in this session. If the tag has an attempt limit (AUTHLIM), " +
                        "each failure counts toward permanently blocking its protected memory. Only continue if you are sure of the password.",
                )
            },
            confirmButton = { TextButton(onClick = { vm.authenticate(confirmedRetry = true) }) { Text("Try once") } },
            dismissButton = { TextButton(onClick = vm::dismissRetryDialog) { Text("Cancel") } },
        )
    }
}

@Composable
private fun ReportContent(r: TagReport, s: ReadUiState, vm: ReadViewModel) {
    val context = LocalContext.current
    SectionCard("General information", icon = Icons.Filled.Info) {
        InfoRow("Tag UID", r.identity.uidDisplay, monospace = true)
        InfoRow("Tag type", "${r.identity.version.productName} (GET_VERSION ${r.identity.version.raw.toHex(" ")})")
        InfoRow("Memory", "${Ntag215Memory.USER_MEMORY_BYTES} bytes user memory (pages 0x04-0x81)")
        val cc = r.identity.cc
        InfoRow(
            "NDEF formatting",
            when {
                cc == null -> "Unknown (CC page protected)"
                cc.isNdefFormatted -> "Formatted, CC $cc (${cc.dataAreaBytes}-byte NDEF area, " + (if (cc.allowsWrite) "read/write)" else "read-only)")
                else -> "Not NDEF formatted (CC $cc)"
            },
        )
        InfoRow("Password protection", r.protection.summary())
        r.config?.let { InfoRow("AUTHLIM", it.describeAuthLim()) }
        r.systemNdef?.let {
            InfoRow(
                "Android NDEF detection",
                if (it.detected) "Detected" + (it.url?.let { u -> " ($u)" } ?: " (no URI record)") else "Not detected on this tap",
            )
        }
    }

    SectionCard("Public data", icon = Icons.Filled.Share) {
        val pa = r.publicArea
        val url = pa.url
        when {
            pa.unreadableReason != null -> MessageCard(pa.unreadableReason, MessageKind.LOCKED)
            url != null -> {
                Text(url, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace)
                FilledTonalButton(onClick = {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    } catch (_: ActivityNotFoundException) {
                    }
                }) { Text("Open URL") }
            }
            pa.isEmpty -> Text("Empty NDEF message (no URL).")
            else -> Text("No URL found.")
        }
        pa.tlv?.takeIf { it.hasNdefTlv }?.let { tlv ->
            InfoRow("NDEF message", "${tlv.ndefLength} bytes, ends at page 0x${Hex.byte(Ntag215Memory.PUBLIC_FIRST_PAGE + (tlv.ndefEndOffset - 1).coerceAtLeast(0) / 4)}")
        }
        pa.records.forEachIndexed { i, rec -> InfoRow("Record ${i + 1}", rec.describe()) }
        pa.error?.takeIf { pa.unreadableReason == null }?.let { MessageCard("NDEF problem: $it", MessageKind.WARNING) }
    }

    SectionCard("Private data", icon = Icons.Filled.Lock) {
        when (val p = r.privateState) {
            PrivateState.Locked -> {
                MessageCard("Private data is password-protected.", MessageKind.LOCKED)
                AuthForm(s, vm)
            }
            is PrivateState.AuthFailed -> {
                MessageCard(p.message + " (failures this session: ${p.failuresThisSession})", MessageKind.ERROR)
                if (!p.blocked) AuthForm(s, vm)
            }
            is PrivateState.Unprotected -> {
                if (!p.area.isBlank) MessageCard("Private data is NOT password-protected on this tag.", MessageKind.WARNING)
                PrivateFields(p.area) { copyToClipboard(context, "Secret", it, sensitive = true) }
            }
            is PrivateState.Authenticated -> {
                MessageCard(
                    "Authenticated. PACK ${p.packHex}" + when (p.packMatches) {
                        true -> " matches."
                        false -> " does NOT match the expected PACK."
                        null -> "."
                    },
                    if (p.packMatches == false) MessageKind.WARNING else MessageKind.INFO,
                )
                PrivateFields(p.area) { copyToClipboard(context, "Secret", it, sensitive = true) }
            }
            is PrivateState.Unavailable -> MessageCard(p.reason, MessageKind.WARNING)
        }
    }

    if (r.warnings.isNotEmpty()) {
        SectionCard("Warnings") { r.warnings.forEach { MessageCard(it, MessageKind.WARNING) } }
    }
    SecurityNote()
}

/** Password used for every scan on this screen. It stays here, editable, between scans. */
@Composable
private fun PasswordCard(s: ReadUiState, vm: ReadViewModel) {
    SectionCard("Password", icon = Icons.Filled.Lock) {
        MaskableField(
            value = s.password,
            onValueChange = vm::onPasswordChange,
            label = "Password (8 hex digits)",
            error = s.passwordError,
            supporting = if (s.hasSavedPassword) "Used on every scan" else "Enter all 8 digits to use it on every scan",
            capitalization = KeyboardCapitalization.Characters,
        )
        OutlinedTextField(
            value = s.pack,
            onValueChange = vm::onPackChange,
            label = { Text("Expected PACK (optional, 4 hex digits)") },
            singleLine = true,
            isError = s.packError != null,
            supportingText = s.packError?.let { { Text(it) } },
            modifier = Modifier.fillMaxWidth(),
        )
        if (s.password.isNotEmpty() || s.pack.isNotEmpty()) {
            TextButton(onClick = vm::clearPassword) { Text("Clear") }
        }
        Text(
            "One attempt per scan. If the password fails on a tag, it is not sent to that tag again until you edit it or press Authenticate.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun AuthForm(s: ReadUiState, vm: ReadViewModel) {
    if (!s.hasSavedPassword) {
        Text("Enter the password above, then press Authenticate or scan the tag again.", style = MaterialTheme.typography.bodyMedium)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { vm.authenticate() }) { Text("Authenticate") }
        if (s.awaitingAuthTap) TextButton(onClick = vm::cancelAuthWait) { Text("Cancel") }
    }
}

@Composable
private fun PrivateFields(area: PrivateArea, onCopy: (String) -> Unit) {
    when (val id = area.id) {
        is PrivateId.Decoded.Valid -> InfoRow("Private ID", id.id.value, monospace = true)
        PrivateId.Decoded.Empty -> InfoRow("Private ID", "(empty)")
        is PrivateId.Decoded.Malformed -> InfoRow("Private ID", "Malformed: ${id.raw.toHex(" ")}", monospace = true)
    }
    when (val sec = area.secret) {
        is Secret.Decoded.Valid -> SecretValue("Secret (32 characters)", sec.secret.value, onCopy = { onCopy(sec.secret.value) })
        Secret.Decoded.Empty -> InfoRow("Secret", "(empty)")
        is Secret.Decoded.Malformed -> InfoRow("Secret", "Malformed: ${sec.reason}")
    }
}

@Composable
fun SecurityNote() {
    MessageCard(
        "NTAG215 password protection only discourages casual copying. The 32-bit password is sent in clear text " +
            "and can be sniffed or brute-forced, and PACK is not cryptographic. Do not rely on it for strong anti-cloning security.",
        MessageKind.INFO,
    )
}
