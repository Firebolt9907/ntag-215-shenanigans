package com.nfcshenanigans.ntag215.ui.write

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.nfcshenanigans.ntag215.core.Password
import com.nfcshenanigans.ntag215.core.Secret
import com.nfcshenanigans.ntag215.data.NfcAvailability
import com.nfcshenanigans.ntag215.nfc.StepStatus
import com.nfcshenanigans.ntag215.nfc.WriteStep
import com.nfcshenanigans.ntag215.ui.common.InfoRow
import com.nfcshenanigans.ntag215.ui.common.MaskableField
import com.nfcshenanigans.ntag215.ui.common.MessageCard
import com.nfcshenanigans.ntag215.ui.common.MessageKind
import com.nfcshenanigans.ntag215.ui.common.NfcStatusBanner
import com.nfcshenanigans.ntag215.ui.common.ScanPrompt
import com.nfcshenanigans.ntag215.ui.common.SecretValue
import com.nfcshenanigans.ntag215.ui.common.SectionCard
import com.nfcshenanigans.ntag215.ui.common.copyToClipboard
import com.nfcshenanigans.ntag215.ui.read.SecurityNote

@Composable
fun WriteScreen(vm: WriteViewModel, nfc: NfcAvailability, onOpenNfcSettings: () -> Unit) {
    val s by vm.state.collectAsStateWithLifecycle()
    val f = s.form
    val editable = s.phase is WritePhase.Editing || s.phase is WritePhase.Failed || s.phase is WritePhase.Succeeded

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        NfcStatusBanner(nfc, onOpenNfcSettings)

        if (s.phase !is WritePhase.Editing) ProgressSection(s, vm)

        SectionCard("Public URL", icon = Icons.Filled.Share) {
            OutlinedTextField(
                value = f.url,
                onValueChange = vm::onUrl,
                label = { Text("https://…") },
                singleLine = false,
                enabled = editable,
                isError = s.errors.url != null,
                supportingText = { Text(s.errors.url ?: s.sizeInfo ?: "Stored as a standard NDEF URI record, readable by any phone") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        SectionCard("Private ID", icon = Icons.Filled.Person) {
            OutlinedTextField(
                value = f.id,
                onValueChange = vm::onId,
                label = { Text("Three digits (000-999)") },
                singleLine = true,
                enabled = editable,
                isError = s.errors.id != null,
                supportingText = { Text(s.errors.id ?: "Stored in page 0x20 as 3 ASCII bytes + 00") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier.fillMaxWidth(),
            )
            CheckRow("Increment ID for the next tag", f.autoIncrementId, editable, vm::onAutoIncrement)
        }

        SectionCard("Private secret", icon = Icons.Filled.Lock) {
            MaskableField(
                value = f.secret,
                onValueChange = vm::onSecret,
                label = "32 ASCII characters",
                error = s.errors.secret,
                supporting = "${f.secret.length}/${Secret.LENGTH} · pages 0x21-0x28",
                extraAction = { TextButton(onClick = vm::generateSecret, enabled = editable) { Text("Generate") } },
            )
            CheckRow("Generate a new secret for the next tag", f.newSecretPerTag, editable, vm::onNewSecretPerTag)
        }

        SectionCard("Authentication", icon = Icons.Filled.Lock) {
            MaskableField(
                value = f.password,
                onValueChange = vm::onPassword,
                label = "New password (8 hex digits)",
                error = s.errors.password,
                supporting = "Written to PWD (page 0x85). Record it: it cannot be read back from the tag.",
                capitalization = KeyboardCapitalization.Characters,
                extraAction = { TextButton(onClick = vm::generatePassword, enabled = editable) { Text("New") } },
            )
            MaskableField(
                value = f.pack,
                onValueChange = vm::onPack,
                label = "PACK (4 hex digits)",
                error = s.errors.pack,
                supporting = "Returned by the tag after authentication (page 0x86)",
                maskedByDefault = false,
                capitalization = KeyboardCapitalization.Characters,
                extraAction = { TextButton(onClick = vm::generatePack, enabled = editable) { Text("New") } },
            )
            CheckRow("New random password and PACK for the next tag", f.newPasswordPerTag, editable, vm::onNewPasswordPerTag)
            MaskableField(
                value = f.currentPassword,
                onValueChange = vm::onCurrentPassword,
                label = "Current password (only for already-protected tags)",
                error = s.errors.currentPassword,
                supporting = "Leave empty for new tags. Tried at most once per write.",
                capitalization = KeyboardCapitalization.Characters,
            )
        }

        Button(
            onClick = vm::startWrite,
            enabled = editable && nfc == NfcAvailability.ENABLED,
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) { Text("Write to NFC Tag", style = MaterialTheme.typography.titleMedium) }

        SecurityNote()
        Spacer(Modifier.height(24.dp))
    }

    when (val p = s.phase) {
        is WritePhase.NeedsConfirmation -> AlertDialog(
            onDismissRequest = vm::cancel,
            title = { Text("Overwrite this tag?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Tag ${p.outcome.uidDisplay} already contains data:")
                    p.outcome.reasons.forEach { Text("• $it") }
                    Text("Existing URL and private data will be replaced. Lock bits are never changed.")
                }
            },
            confirmButton = { TextButton(onClick = { vm.confirmOverwrite(p.outcome.uidHex) }) { Text("Overwrite") } },
            dismissButton = { TextButton(onClick = vm::cancel) { Text("Cancel") } },
        )
        is WritePhase.NeedsPassword -> PasswordDialog(p, f.currentPassword, vm)
        else -> Unit
    }
}

@Composable
private fun PasswordDialog(p: WritePhase.NeedsPassword, initial: String, vm: WriteViewModel) {
    var pwd by remember { mutableStateOf(initial) }
    val err = if (pwd.isEmpty()) null else Password.validate(pwd)
    val failures = p.outcome.failuresThisSession
    AlertDialog(
        onDismissRequest = vm::cancel,
        title = { Text("Tag is password-protected") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Tag ${p.outcome.uidDisplay}: ${p.outcome.protectionSummary}. Enter its current password.")
                if (failures > 0) {
                    MessageCard(
                        "$failures failed attempt(s) this session. If AUTHLIM is set on this tag, failures count toward permanently blocking it.",
                        MessageKind.WARNING,
                    )
                }
                MaskableField(
                    value = pwd,
                    onValueChange = { v -> pwd = v.filter { Character.digit(it, 16) >= 0 }.uppercase().take(8) },
                    label = "Current password",
                    error = err,
                    capitalization = KeyboardCapitalization.Characters,
                )
            }
        },
        confirmButton = {
            TextButton(enabled = Password.parse(pwd) != null, onClick = { vm.supplyCurrentPassword(pwd) }) {
                Text(if (failures > 0) "Try once more" else "Authenticate once")
            }
        },
        dismissButton = { TextButton(onClick = vm::cancel) { Text("Cancel") } },
    )
}

@Composable
private fun ProgressSection(s: WriteUiState, vm: WriteViewModel) {
    val context = LocalContext.current
    when (val p = s.phase) {
        is WritePhase.WaitingForTag -> ScanPrompt(p.message)
        WritePhase.Running -> ScanPrompt("Writing… keep the tag still", busy = true)
        else -> Unit
    }
    SectionCard("Progress", icon = Icons.Filled.Edit) {
        WriteStep.entries.forEach { step ->
            val ui = s.steps[step]
            StepRow(step, ui?.status ?: StepStatus.PENDING, ui?.detail)
        }
        if (s.phase is WritePhase.WaitingForTag || s.phase is WritePhase.Running) {
            OutlinedButton(onClick = vm::cancel, enabled = s.phase is WritePhase.WaitingForTag) { Text("Cancel") }
        }
    }
    when (val p = s.phase) {
        is WritePhase.Succeeded -> SectionCard("Success") {
            val r = p.outcome.report
            MessageCard("Tag written, protected and verified.", MessageKind.INFO)
            InfoRow("UID", r.uidDisplay, monospace = true)
            InfoRow("URL", r.url)
            InfoRow("Private ID", r.id.value, monospace = true)
            InfoRow("Encoded size", "${r.tlvSize} bytes")
            SecretValue("Password", r.passwordHex) { copyToClipboard(context, "Password", r.passwordHex, sensitive = true) }
            InfoRow("PACK", r.packHex, monospace = true)
            r.checks.forEach { Text("✓ $it", style = MaterialTheme.typography.bodySmall) }
            r.notes.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
            Text("Tags written this session: ${s.tagsWritten}", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::nextTag) { Text("Configure next tag") }
                OutlinedButton(onClick = vm::finish) { Text("Done") }
            }
        }
        is WritePhase.Failed -> SectionCard("Write failed") {
            val o = p.outcome
            MessageCard("Step ${o.step.number} failed: ${o.step.label}\n${o.error.message}", MessageKind.ERROR)
            MessageCard(o.tagState, if (o.tagState.startsWith("No data")) MessageKind.INFO else MessageKind.WARNING)
            if (!o.error.recoverable) Text("This problem will not go away by retrying.", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::retry) { Text("Try again") }
                OutlinedButton(onClick = vm::cancel) { Text("Edit") }
            }
        }
        else -> Unit
    }
}

@Composable
private fun StepRow(step: WriteStep, status: StepStatus, detail: String?) {
    val color = when (status) {
        StepStatus.DONE -> MaterialTheme.colorScheme.primary
        StepStatus.FAILED -> MaterialTheme.colorScheme.error
        StepStatus.RUNNING -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(verticalAlignment = Alignment.Top) {
        Column(Modifier.width(28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            when (status) {
                StepStatus.RUNNING -> CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                else -> Text(
                    when (status) {
                        StepStatus.DONE -> "✓"; StepStatus.FAILED -> "✗"; StepStatus.SKIPPED -> "–"; else -> "○"
                    },
                    color = color,
                )
            }
        }
        Column {
            Text("${step.number}. ${step.label}", color = if (status == StepStatus.PENDING) Color.Gray else MaterialTheme.colorScheme.onSurface)
            detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = color) }
        }
    }
}

@Composable
private fun CheckRow(label: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange, enabled = enabled)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}
