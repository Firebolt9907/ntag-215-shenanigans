# NTAG215 Tool

A native Android app (Kotlin, Jetpack Compose, Material 3) for writing, reading and password-protecting
NXP **NTAG215** tags with:

1. a **public URL** — a standard NDEF URI record any phone can open without this app;
2. a **private 3-digit ID** (`000`–`999`);
3. a **private 32-character ASCII secret**.

The ID and secret are protected with the NTAG215's native 32-bit password (`PWD_AUTH`), with read and write
protection starting at page `0x20`.

> **Security note:** NTAG215 password protection only discourages casual cloning with ordinary NFC apps. The
> password crosses the air in clear text, can be sniffed or brute-forced, and PACK is not cryptographic.
> Do not treat it as strong anti-cloning security. NXP says the same in datasheet §8.8.

---

## Requirements and build

| | |
|---|---|
| Android Studio | Ladybug or newer (AGP 8.13, Gradle 8.14.3, Kotlin 2.2.21) |
| JDK for Gradle | 17–21 (Android Studio's bundled JBR 21 works; **JDK 25 is not supported by Gradle 8.14**) |
| compileSdk / targetSdk / minSdk | 36 / 36 / 26 |
| Device | Any Android 8.0+ phone with NFC. No root and no external reader needed. |

`build.sh` finds Android Studio's bundled JDK 21 and runs Gradle with it, whatever your `JAVA_HOME` is.
Set `ANDROID_STUDIO_JDK` to use a different JDK 21.

```bash
./build.sh                            # build and install on the connected device
./build.sh :app:assembleDebug         # build only. APK: app/build/outputs/apk/debug/app-debug.apk
./build.sh :app:testDebugUnitTest     # 104 unit/scenario tests, no hardware needed
```

Or open the folder in Android Studio and run the `app` configuration.

---

## Using the app

The bottom bar has three screens. While the app is in the foreground it uses NFC **reader mode**, so tags are
delivered to the visible screen and not to other apps.

### Write
1. Enter the **URL**. The field shows the exact encoded size, for example
   `73 of 112 bytes (pages 0x04-0x16, 39 free)`. URLs that would reach page `0x20` are rejected.
2. Enter a **3-digit ID**. Leading zeros are kept.
3. Enter a **32-character secret** or tap **Generate** (SecureRandom, alphanumeric). It is masked by default.
4. **Password** (8 hex digits) and **PACK** (4 hex digits) are random by default. Record the password: it can
   never be read back from a tag.
5. For a tag that is already protected, fill in **Current password**, or enter it when prompted.
6. Tap **Write to NFC Tag** and hold the tag to the phone. Progress shows 14 steps. If anything fails, the app
   reports the exact step and what state the tag was left in.

If the tag already holds a URL, private data or a password, the app asks for confirmation first. That
confirmation is tied to the tag's UID. You can keep the tag in place while answering dialogs, or tap it again.

To configure many tags in a row, tap **Configure next tag** after a success. The ID is incremented and a new
secret, password and PACK are generated (each of these is optional) before the app waits for the next tag.

### Read
The **Password** card at the top stays filled in between scans. When it holds all 8 hex digits (plus an
optional PACK), every scan of a protected tag tries it once and shows the private data straight away. Edit it
at any time for the next scan, or tap **Clear**. If the password fails on a tag, it is not sent to that tag
again automatically, because AUTHLIM can count every failure. Edit the password or press **Authenticate** to
try again.

Scan any tag to see:
- **General information:** UID, type, memory, NDEF formatting, protection, AUTHLIM, and whether *Android's own*
  NDEF detection found the URL on that tap. That last item is what background scanning sees.
- **Public data:** the URL with an **Open URL** button, plus record details.
- **Private data:** "Private data is password-protected." with an **Authenticate** button. After a successful
  authentication it shows the ID and the secret (masked, with **Reveal** and **Copy**).

### Advanced
- Raw memory viewer for all 135 pages: address, hex, ASCII and purpose. Protected pages show 🔒 until you
  authenticate. Private pages stay masked until you reveal them.
- Decoded CC, static and dynamic lock bits, and the CFG0/CFG1 fields (AUTH0, PROT, CFGLCK, AUTHLIM, NFC
  counter, ASCII mirror).
- Diagnostics: device, techs, ATQA/SAK, max transceive length, and whether FAST_READ was used.
- Command log: command names and outcomes only. **No data, passwords or secrets are ever logged**, and the app
  writes nothing to logcat.
- **Remove password protection…** sets AUTH0 = FFh and PROT = 0, after confirmation and one authentication.

---

## Memory layout

| Pages | Content | Access after configuration |
|---|---|---|
| 0x00–0x03 | UID, static lock bytes, Capability Container | public, **never written by the app** |
| 0x04–0x1F | NDEF TLV with one URI record, then Terminator TLV, zero padded (112 bytes) | public read; writable without password |
| 0x20 | ID: 3 ASCII digits + `00` (`042` → `30 34 32 00`) | password |
| 0x21–0x28 | Secret, 32 ASCII bytes | password |
| 0x29–0x81 | Reserved, untouched | password |
| 0x82 | Dynamic lock bytes, **never written** | password |
| 0x83 | CFG0: MIRROR, RFUI, MIRROR_PAGE, **AUTH0 = 0x20** | password |
| 0x84 | CFG1: ACCESS (**PROT = 1**, other bits preserved) | password |
| 0x85 / 0x86 | PWD / PACK (always read as 00) | password |

### Encoded URL size
Total size is TLV header (2) + record header (`D1 01 len 55` = 4) + prefix code (1) + rest of the URL in UTF‑8,
plus the Terminator TLV (1). The longest standard prefix is compressed, for example `https://www.` → `0x02`.
The public region holds 112 bytes:

- `https://…` URLs can be up to **112 characters** (8 + 104).
- `https://www.…` URLs can be up to **116 characters**.
- A typical 77-character `https://www.` URL uses 73 bytes, which is pages 0x04–0x16.

---

## Investigation: public scanning while later pages are read-protected

The specification asked whether protecting page 0x20 onward breaks ordinary background URL scanning. I checked
this against the **NXP NTAG213/215/216 datasheet Rev. 3.2** and the **AOSP NFC stack source**
(`system/nfc` and `packages/apps/Nfc`, android14/15 branches).

**Datasheet facts the design relies on**
- §10.2 READ: when read-protected and not authenticated, reading a page **below AUTH0 returns data and rolls
  over just before AUTH0**. Only addressing a page ≥ AUTH0 gives a NAK. A 16-byte READ that starts in the
  public area therefore never fails because the private area follows it.
- §10.3 FAST_READ NAKs if *any* requested page is ≥ AUTH0. The app only FAST_READs ranges it is allowed to
  read.
- §8.4: after a NAK the tag goes to IDLE/HALT and the authenticated state is lost, so the reader must
  re-activate the tag.
- §8.5.4: the CC is OTP (writes are bit-wise ORed) and cannot be undone. **The app never writes the CC.**
- §8.8.1–8.8.3: AUTH0 = first protected page; PROT selects write-only or read+write protection; PWD/PACK
  read as 00; AUTHLIM = 000b means unlimited attempts.

**How Android reads NDEF (AOSP `rw_t2t_ndef.cc`, `nfa_rw_act.cc`)**
- The stack reads the CC and the TLVs with **aligned 4-page READs**. With AUTH0 = 0x20, which is a multiple
  of 4, the last NDEF block read is 0x1C–0x1F and is never refused.
- It also tries to read the **dynamic lock bytes** (at the end of the data area) to decide whether the tag is
  writable. These sit at or above AUTH0 and are always protected, so that read NAKs.
- The stack handles this case explicitly. On `NFC_STATUS_REJECTED` it does a sleep/wake-up of the tag. If NDEF
  detection failed, `nfa_rw_handle_t2t_evt` **retries detection with `skip_dyn_locks = true`**, and that
  attempt succeeds. The tag is reported as NDEF and the URL is dispatched normally.
- In the JNI layer, a raw `transceive()` that gets a T2T NAK re-selects the tag itself and throws
  `IOException`. The app's command layer handles that path as well as controllers that return the 4-bit NAK
  as a byte.

**Conclusion and implemented behaviour**
- On AOSP-based Android, the layout above (AUTH0 = 0x20, PROT = 1, factory CC `E1 10 3E 00`) keeps the URL
  readable in the background.
- No CC change is needed, so none is made. Setting CC3 to read-only (`0x0F`) would make Android skip the lock
  read, but it is **irreversible** and tells every reader the tag is read-only, so it is deliberately not done.
- The Read screen shows **"Android NDEF detection"** on every tap, using the platform's own cached result.
  You can confirm the behaviour on your exact phone.

**Unverified items (no physical tag was available while building):**
- **iOS** background tag reading is closed source and was not checked. Run test 7 below on an iPhone (XS or
  later) before deploying tags widely.
- **Vendor NFC stacks** (Samsung, older NXP/Broadcom controllers) may differ from AOSP. Test 7 also covers them.
- **Limitation:** pages 0x04–0x1F stay **writable without a password**, because AUTH0 protects everything
  from one page to the end of memory. Anyone with a tag-writer app could overwrite the URL, but not read or
  change the private data. Making the URL tamper-proof needs irreversible lock bits or an irreversible CC
  change, and the app never sets either.

---

## Safety measures

- The chip is verified with GET_VERSION (NTAG215 = `00 04 04 02 01 00 11 03`) before any write. Other tags
  are refused.
- The command layer **refuses to write** pages 0x00–0x03 (UID, static locks, CC) and 0x82 (dynamic locks).
  Lock bits and CFGLCK are never set.
- The app never assumes a factory state. Existing configuration is read first, and only AUTH0 and the PROT bit
  are changed. MIRROR, MIRROR_PAGE, RFUI bytes, CFGLCK, NFC_CNT_EN, NFC_CNT_PWD_PROT and **AUTHLIM are
  preserved**. Unit tests check this.
- Writing is refused (with nothing written) if the CC is read-only or unformatted, any page 0x04–0x28 is
  locked, CFGLCK blocks the required change, or an ASCII mirror overlaps the data.
- Tearing-aware order:
  1. Write the NDEF TLV length as 0, then the body, then the real length.
  2. Write the private data and read everything back.
  3. Write PWD and PACK, then **verify the new password with PWD_AUTH before enabling protection**.
  4. Write ACCESS, then **AUTH0 last**.
  5. Re-verify without authentication and with authentication.
- Passwords:
  - There is exactly one `PWD_AUTH` per user action, and passwords are never guessed or retried.
  - Failures are counted per UID, and another attempt needs explicit confirmation, because AUTHLIM can
    permanently lock a tag.
  - Re-authentication only uses a password the tag already accepted in that session.
- Success is reported only after every verification step passes. On failure the app says whether the tag is
  unchanged, partially written, or may already use the **new** password.
- NFC I/O runs on `Dispatchers.IO` behind a mutex and never on the main thread.

---

## Code structure

```
core/   Pure Kotlin, unit-tested
  Hex.kt               hex/ASCII conversion
  Ntag215Memory.kt     memory map, page math, never-writable pages
  Ntag215Config.kt     GET_VERSION, CC, static/dynamic lock bits, CFG0/CFG1 bit manipulation
  NdefUrlEncoder.kt    URL validation, URI prefix table, NDEF record/TLV encoding and parsing
  PrivateData.kt       PrivateId, Secret (CSPRNG generator), Password, Pack
nfc/
  NfcTransport.kt      transport interface + Android NfcA implementation
  NfcCommandExecutor.kt READ/FAST_READ/WRITE/PWD_AUTH/GET_VERSION framing, NAK handling, chunking
  Ntag215Authenticator.kt single-attempt policy, attempt tracking
  Ntag215Manager.kt    identify, protection probing, inspect, dump, 14-step write, remove protection
  TagModels.kt, NtagException.kt, CommandLog.kt
data/Ntag215Repository.kt  reader-mode tag routing, IO dispatcher + mutex
ui/                    Compose screens (Read, Write, Advanced), Material 3 + dynamic color
```

Tests live in `app/src/test`. `FakeNtag215` is a software NTAG215 that follows the datasheet: READ roll-over
before AUTH0, FAST_READ NAK, OTP CC and lock OR semantics, CFGLCK, PWD/PACK read as 00, AUTHLIM counter, the
IDLE state after a NAK, and simulated tag removal. Every scenario runs with both NAK delivery styles.

---

## Integration testing with real NTAG215 tags

Use genuine NXP NTAG215 tags. Some cheap "NTAG215-compatible" clones behave differently. Check AUTHLIM on the
Advanced screen before testing wrong passwords. For each scenario, also look at the Advanced command log.

| # | Scenario | Procedure | Expected |
|---|---|---|---|
| 1 | Fresh NTAG215 | Write screen: URL, ID `042`, Generate secret, Write, tap a new tag. | All 14 steps ✓. Advanced (authenticated): `0x83 = 04 00 00 20`, `0x84 = 80 00 00 00`. |
| 2 | Tag with existing URL | Write a URL with any NDEF app, then write it with this app. | "Overwrite this tag?" lists the old URL. Cancel changes nothing; Overwrite succeeds. |
| 3 | Existing protection | Write tag from #1 again with Current password empty. | Password dialog appears; no PWD_AUTH is sent before you answer. With the right password → confirmation → success. |
| 4 | Incorrect password | Read screen → Authenticate with a wrong password. | "Authentication failed… No further attempts were made." A second attempt asks for confirmation. Tag unchanged. |
| 5 | URL too long | Enter `https://` + 105+ characters. | Field error with the byte count; Write is blocked. |
| 6 | Tag removed while writing | Start a write and pull the tag away quickly (repeat until it happens mid-write). | "Step N failed …" plus a tag-state note. Re-tapping completes the write after confirmation. |
| 7 | **Public scan after protection** | Close the app, unlock the phone, tap the protected tag. Repeat on other Android brands and **an iPhone (XS or later)**. | The browser opens the URL. On Android the Read screen also shows "Android NDEF detection: Detected". |
| 8 | Unauthenticated private read fails | Read the tag with a generic NFC app (e.g. NXP TagInfo, NFC Tools) and on this app's Advanced screen without a password. | Pages ≥ 0x20 are unreadable or 🔒; ID and secret are not shown. |
| 9 | Authenticated private read | Read screen → enter the password (and PACK) → Authenticate. | ID and secret (masked, Reveal/Copy) are shown; "PACK … matches". |
| 10 | Rewrite configured tag | Write new values with Current password = old password and a new password. | Success; the old password fails afterwards and the new one works. |

To reset a tag for re-testing, use Advanced → **Remove password protection…** (this is reversible).

### Hardware-dependent behaviour not verified in this build
- Real RF timing, the transceive limit and FAST_READ support on your phone. FAST_READ falls back to READ
  automatically.
- How your phone reports NAKs, as an exception or as a byte. Both are handled and unit-tested, but not
  checked on hardware.
- That `NfcA.close()` + `connect()` re-selects the tag. AOSP source shows it does. The app also sends an
  invalid READ to force de-authentication before its "protection effective" check.
- Whether `PWD_AUTH` is accepted while AUTH0 = FFh, which the app uses to verify the new password before
  enabling protection. If a tag rejects it, the write stops with "Protection was NOT enabled" (a safe
  failure), and protection is never left in an unknown state.
- iOS and non-AOSP Android background reading of read-protected NTAG215 tags (test 7).
