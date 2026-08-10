# Common Issues

This guide covers the most frequently encountered issues when using friTap and provides step-by-step solutions.

!!! tip "Log to a file — don't pipe friTap's stdout into `head` or `grep`"
    During a capture friTap writes everything to **stderr**, so `fritap ... | grep -i hook`
    filters an empty stream: stdout carries nothing. Adding
    `2>&1` makes the pipe work, but a file is still the better tool — it survives
    the session, captures the crash reports friTap collects, and can be
    re-searched without re-running the capture:

    ```bash
    fritap --debug-log ./debug.log -do -v -k keys.log target_app
    grep -i "hook\|error" ./debug.log
    ```

    Every example on this page follows that rule.

## friTap crashes the target application immediately

**Symptom**: the target dies within a second or two of friTap attaching or
spawning it. friTap reports a detach with reason `process-terminated`, and you get
no keys and no plaintext.

**Cause**: almost always **one specific hook**, not friTap as a whole — a wrong
offset for this exact library build, an inline patch an anti-tamper runtime
noticed, or a hook installed while the target was suspended. Occasionally it is
Frida itself, or the spawn/resume dance rather than any hook.

The only reliable way to tell these apart is to bisect.

### Fix — the bisection ladder

Work down the ladder. Each step removes one suspect.

**Step 0 — `--probe`: does the agent even load?**

```bash
fritap -m --probe com.example.app
```

`--probe` loads the friTap agent, has it report the platform branch it selected,
and then **exits without installing any TLS hooks**.

- **Target survives** → the agent bootstrap, the Frida attach and the config
  handshake are all fine. **The crash is in hook installation.** Continue down the
  ladder.
- **Target dies anyway** → the crash is *not* in TLS hook installation. Go to
  step 1.

Two caveats before you trust a probe run:

- **`-c/--custom_script` hooks are still installed under `--probe`.** Drop `-c`
  for a clean probe.
- **On Android**, the bundle's `frida-java-bridge` initialises during
  `script.load()`, installing a hook before `probe` is even read. Probe mode
  means "no *TLS* hooks", not "zero target mutation".

If friTap exits with code **2** and prints
`--probe failed: the loaded agent bundle does not implement probe mode`, your
agent bundle predates probe mode — rebuild it (see
[the rebuild rule](#i-edited-agentts-and-nothing-changed-the-rebuild-rule)) and
re-run. Do **not** interpret that run: hooks may well have been installed.

**Step 1 — control experiment: is it friTap or Frida?**

Run Frida with **no script at all**:

```bash
frida -U -f com.example.app          # mobile
frida -f /path/to/binary             # desktop
```

- **Dies here too** → the problem is Frida/injection on this target (anti-debug,
  code signing, a jailbreak/root detector), not friTap's hooks. Nothing in friTap
  will fix it.
- **Survives** → friTap adds the fatal ingredient. Keep going.

**Step 2 — attach instead of spawn.**

Drop `-s`. Start the app by hand, let it settle, then attach:

```bash
fritap -m -k keys.log com.example.app        # no -s
```

Spawn mode installs hooks while the process is suspended and during the target's
most fragile window (startup, integrity checks, watchdog timers). Attach mode
misses early handshakes but survives far more often. **If attach works and spawn
does not, the crash is startup-timing, not a bad hook.**

**Step 3 — on Apple: try `--modern`.**

```bash
fritap --modern -k keys.log -s /Applications/Example.app/Contents/MacOS/Example
```

The `--modern` code path **does not write into the `SSL_CTX` struct at all**.

!!! warning "This test is asymmetric — read it in one direction only"
    - **Surviving under `--modern` is informative**: it points at a **wrong
      keylog offset** on the legacy path (friTap wrote a callback pointer into
      the wrong field of `SSL_CTX` for this build).
    - **Dying under `--modern` proves nothing.** `--modern` installs hooks of its
      own, so its crash may have a completely different cause.

    Also remember `--modern` has known regressions vs. the legacy default:
    iOS/macOS Cronet, Windows LSASS, IPsec.

See [macOS](../platforms/macos.md), [iOS](../platforms/ios.md) and
[BoringSSL](../libraries/boringssl.md) for how the Apple keylog offset is
derived.

**Step 4 — narrow the hook set.**

```bash
# Android, anti-tamper suspected
fritap -m -k keys.log --pairip-safe com.example.app
fritap -m -k keys.log --no-loader-hook com.example.app

# Skip TLS-library hooks entirely (Android/Linux)
fritap -m -k keys.log --quic-only com.example.app

# Hook exactly one library at a known offset
fritap -m -k keys.log --offsets offsets.json com.example.app
```

### What friTap already tells you

You usually do not have to go hunting for the crash report — friTap collects it.

**It captures native crash reports automatically:**

| Source | What friTap collects |
| --- | --- |
| Frida | The `Crash` object's report and summary, written under `===== NATIVE CRASH REPORT (frida) =====` |
| Android | `logcat -b crash -d` output, plus the latest **tombstone** for the crashed PID |
| iOS | The latest `.ips` crash report, pulled with `idevicecrashreport`, plus a decoded summary |

**All of it lands in the debug log even without `--debug`.** friTap opens
`./fritap_debug_<ts>_<pid>.log` on a crash whether or not you asked for debug
output. Point it somewhere else with `--debug-log <path>` or the
`FRITAP_DEBUG_LOG` env var.

**It reports the last hook breadcrumb.** The agent continuously reports the stage
it is in; on a crash friTap prints the last one it saw:

| Breadcrumb prefix | Meaning |
| --- | --- |
| `agent-init: <stage>` | *"The agent died before any hook was installed."* Stages: `config-handshake`, `anti-handshake`, `pipeline-init`, `platform-detect`, `platform-load`, `region-scan`, `complete` |
| `agent-init-FAILED: <stage>` | The named init stage itself threw |
| `install-phase: <platform>/<phase>` | *"The agent died while installing hooks."* The phase label tells you which hook group |
| *(empty)* | *"The agent never reported a startup stage."* — it died before the first breadcrumb |

An `agent-init*` breadcrumb means the crash is **not** a bad hook offset — look at
injection, code signing, or the handshake. An `install-phase*` breadcrumb names the
hook group to disable next.

### Decoded iOS terminators

For iOS targets friTap parses the `.ips` report and explains the terminator:

| Terminator | Meaning | What to try |
| --- | --- | --- |
| `0x8badf00d` | **Watchdog timeout** ("ate bad food") — the app was suspended or blocked too long and the watchdog killed it | The signature of a gated/suspended app that was never resumed. Make sure friTap resumes the spawned process after hooks are installed, or **attach** to the running app instead of spawning |
| jetsam / `per-process-limit` | Killed for **memory pressure** | Reboot / close other apps; reduce friTap's on-device footprint (large full-capture buffers make this likelier) |
| `EXC_BAD_ACCESS` | Bad memory access — **usually a wrong hook offset** | Verify the offsets/patterns for this exact library build; disable the suspect hook to confirm |
| `0xdead10cc` | ("dead lock") the app held a file lock or an open SQLite database while being suspended in the background | Keep the app in the foreground during the capture |
| codesigning / `CS_INVALID` | Signature rejected by **AMFI** | Re-sign the app and frida-server with valid entitlements (`ldid -S<entitlements.xml>`, verify with `ldid -e`) |
| `EXC_CRASH` under SPRINGBOARD/FRONTBOARD | System watchdog / launch services — the app did not come up in time under instrumentation | Fewer hooks, no pattern scan at launch, or attach instead of spawn |

!!! warning "Status: the iOS crash-report path has never been exercised against a real device"
    The parsing and decoding above are unit-tested, but the end-to-end pull from a
    physical iPhone is **unvalidated**. Treat its output as a strong hint, not
    ground truth, and please report what you see.

    It also needs `libimobiledevice`, which is declared in **no** friTap
    dependency file:

    ```bash
    brew install libimobiledevice
    ```

## I edited `agent/*.ts` and nothing changed — the rebuild rule

**Symptom**: you changed something under `agent/`, re-ran friTap, and the
behaviour is byte-for-byte identical. Or: a fix "works" and you cannot explain
why.

**Cause**: friTap loads the **pre-compiled** bundle `friTap/fritap_agent.js`.
**Nothing rebuilds the TypeScript at run time.** Editing `agent/*.ts` has zero
effect on a friTap run until you compile.

**Fix**:

```bash
./dev/compile_agent.sh
```

!!! danger "Confirm the success line — do not assume it built"
    A successful build ends with:

    ```
    [compile_agent.sh] done. Agent: 2731554 bytes
    ```

    If you do **not** see that `done. Agent: <N> bytes` line, the compile failed
    and the **previous bundle is still sitting at `friTap/fritap_agent.js`**. A
    later run then silently exercises **stale** code — and may "pass" for
    entirely the wrong reason. Scroll up for `frida-compile`'s error output.

    `tsc --noEmit` is *not* a substitute: it can succeed while the bundle build
    fails.

**Checking which bundle is loaded.** friTap resolves the agent bundle in this
order:

1. **`FRITAP_AGENT_BUNDLE`** env var — an absolute or `~`-relative path to a
   `.js` bundle. Always wins, and is **not** ABI-filtered.
2. A `fritap.agent_bundle` **entry point** contributed by an installed package —
   used only if it declares a **matching** agent ABI.
3. The **shipped** bundle, `friTap/fritap_agent.js`.

```bash
FRITAP_AGENT_BUNDLE=/path/to/my_agent.js fritap -m -k keys.log com.example.app
```

**The agent ABI.** `friTap/constants.py:AGENT_ABI_VERSION` versions the whole
JS ↔ Python boundary (the `config_batch` fields, the `ContentType` values, the
`rpc.exports` surface). It is currently **2**.

- A **stale shipped bundle** produces a warning naming *both* versions and telling
  you to run `./dev/compile_agent.sh`.
- An **ABI-mismatched entry-point bundle** is **skipped with a warning** and
  friTap falls back to the shipped agent — so a third-party bundle can silently
  not be in use.

Full detail: [Standalone agent — Agent ABI version](../advanced/standalone-agent.md#agent-abi-version).

!!! info "Only relevant to git checkouts"
    A `pip install fritap` ships an already-compiled bundle. If you installed from
    PyPI there is nothing to rebuild — and no `dev/compile_agent.sh`. This is why
    bug reports must say **which** kind of install they are (see
    [Information to Provide](#information-to-provide)).

## Installation Issues

### friTap Installation Fails

**Issue**: `pip install fritap` fails with dependency errors.

**Solutions**:

```bash
# Update pip and setuptools
python -m pip install --upgrade pip setuptools

# Install with verbose output to see error details
pip install -v fritap

# Try installing dependencies separately
pip install frida frida-tools
pip install fritap
```

**Common Dependency Issues**:
```bash
# macOS: Install Xcode Command Line Tools
xcode-select --install

# Linux: Install development packages
sudo apt update && sudo apt install python3-dev build-essential

# Windows: Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
```

### Frida Version Conflicts

**Issue**: `frida version mismatch` errors.

**Solutions**:
friTap's `requirements.txt` allows a **range**, not a single version:

```
frida>=17.0.0,<18.0.0
frida-tools>=14.0.0,<15.0.0
```

```bash
# Check frida versions
pip list | grep frida
frida --version

# Reinstall within the supported range (do not over-pin)
pip uninstall frida frida-tools
pip install "frida>=17.0.0,<18.0.0" "frida-tools>=14.0.0,<15.0.0"

# Verify friTap compatibility
fritap --version
```

!!! note "The frida-server on the device must match the Python `frida` version"
    A `frida version mismatch` error almost always means the on-device
    frida-server is a different version from the host `frida` package — not that
    the host package is wrong. Update the *server* to match, rather than pinning
    the host down to an old release.

## Permission Issues

### Permission Denied (Desktop)

**Issue**: `Permission denied` when analyzing desktop applications.

**Solutions**:

=== "Linux"
    ```bash
    # Use sudo
    sudo fritap -k keys.log firefox
    
    # Add user to appropriate groups
    sudo usermod -a -G root $USER
    newgrp root
    
    # Check process ownership
    ps aux | grep firefox
    sudo fritap $(pgrep firefox) -k keys.log
    ```

=== "macOS"
    On macOS the blocker is usually **not** privileges. `sudo` alone does not get
    you a task port for another process. Two separate gates apply:

    **1. System Integrity Protection.** Attaching to another local process
    normally requires SIP to be **disabled**:

    ```bash
    csrutil status        # expect: System Integrity Protection status: disabled
    # To change it: boot into Recovery (hold the power button on Apple silicon)
    # and run: csrutil disable
    ```

    **2. Code signing of the target.** Even with SIP off, injection is refused
    when the target has the **hardened runtime** or **library validation**
    enabled, or simply lacks the `com.apple.security.cs.get-task-allow`
    entitlement. Apple-signed apps (Safari, Mail, ...) fall into this bucket —
    `sudo fritap -k keys.log Safari` fails for signing reasons, and no amount of
    privilege fixes it. Options: re-sign the app with `get-task-allow`, or test
    against a build you control.

    ```bash
    codesign -d --entitlements - /Applications/Example.app        # inspect
    codesign -dv --verbose=4 /Applications/Example.app 2>&1 | \
        grep -i "flags\|runtime"
    ```

    Full detail: [macOS platform guide](../platforms/macos.md).

=== "Windows"
    ```cmd
    REM Run as Administrator
    fritap -k keys.log chrome.exe
    
    REM Check process privileges
    whoami /priv
    ```

### Mobile Device Access Issues

**Issue**: Cannot connect to Android/iOS device.

**Solutions**:

**Android**:
```bash
# Check device connection
adb devices

# Enable USB debugging
# Settings → Developer Options → USB Debugging

# Verify root access
adb shell su -c "id"

# Check frida-server
adb shell ps | grep frida-server

# Restart frida-server
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

**iOS**:
```bash
# Check SSH connection
ssh root@device-ip

# Verify frida installation
ssh root@device-ip "frida-ps"

# Restart frida-server
ssh root@device-ip "killall frida-server; frida-server &"
```

## Library Detection Issues

### friTap runs but captures no keys

**Issue**: friTap attaches, prints no error, and the keylog stays empty (or is
never created).

!!! note "There is no \"No SSL library found\" message"
    friTap does **not** emit `No SSL library found` or `No hooks installed` — if
    you are searching a log for those strings you will never find them. The real
    symptom is simply the absence of key material. Judge it by the output, not by
    an error line.

**Diagnostic Steps**:

```bash
# Enable debug output into a file (see the logging note at the top of this page)
fritap -do -v --debug-log ./debug.log target_app
grep -i "library\|found\|hook\|symbol" ./debug.log

# List loaded libraries. NOTE: this exits WITHOUT capturing anything.
fritap --list-libraries target_app > libs.txt
grep -i ssl libs.txt
```

!!! info "`-ll/--list-libraries` is not a capture run"
    It lists the loaded libraries and **exits**. Nothing is hooked and no keys
    are written, so an empty keylog after `--list-libraries` is expected, not a
    bug. Same for `--extract-libraries <dir>`.

**Solutions**:

**Use Pattern-Based Hooking**:

friTap can locate key functions by **byte pattern** when symbols are stripped or
missing — for BoringSSL that target is **`ssl_log_secret()`** (there is no
`ssl_log()` function). Library updates break these patterns, especially on
stripped binaries; when that happens you can supply your own byte-pattern
definitions.

```bash
# For stripped libraries
fritap --patterns patterns.json -k keys.log target_app
```

Generate patterns with BoringSecretHunter — see
[Flutter Applications](#flutter-applications) below, and
[Pattern-based hooking](../advanced/patterns.md) for the schema.

**Force a scan friTap skipped:**

```bash
# friTap can decide a module is covered by a sibling library (Cronet APEX split)
fritap --force-scan libmainlinecronet.141.0.7340.3.so -m -k keys.log com.example.app

# Same thing via the environment (comma-separated)
FRITAP_FORCE_SCAN=libmainlinecronet.141.0.7340.3.so fritap -m -k keys.log com.example.app
```

### Library Detected but No Hooks

**Issue**: Library detected but no function hooks installed.

**Solutions**:
```bash
# Check symbol availability
fritap -do -v --debug-log ./debug.log target_app
grep -i symbol ./debug.log

# Use offset-based hooking
fritap --offsets offsets.json -k keys.log target_app

# Try manual function resolution
fritap -c custom_hooks.js -k keys.log target_app
```

## Traffic Capture Issues

### No Traffic Captured

**Issue**: friTap runs successfully but no traffic is captured.

**Common Causes and Solutions**:

**Socket Information Issues**:
```bash
# Use default socket information
fritap --enable_default_fd --pcap traffic.pcap target_app

# Enable full capture mode (-f REQUIRES -p to name the pcap)
fritap --full_capture -p traffic.pcap -k keys.log target_app
```

!!! warning "`--full_capture` without `-p` is rejected"
    `fritap --full_capture -k keys.log target_app` never captures: the argument
    parser stops it with
    `Error: --full_capture requires -p to set the pcap name` and prints the help
    text. `-f` always needs `-p <path>`.

**Child Process Issues**:

Two different flags for two different things:

| Flag | What it catches |
| --- | --- |
| `--enable_child_gating` | **Child processes spawned by the target** (fork/clone) — this is the one you want for Electron, Chrome, and any multi-process desktop app |
| `--enable_spawn_gating` | Newly spawned processes **matching the target app name** — an Android multi-process-app mechanism |

```bash
# Intercept the target's own children (Electron renderers, Chrome zygotes, ...)
fritap --enable_child_gating -p traffic.pcap target_app

# Android multi-process app: catch its other processes as they start
fritap -m --enable_spawn_gating -k keys.log com.example.app

# Or target one specific child directly by PID
fritap $(pgrep -f "child_process") -k keys.log
```

## Mobile-Specific Issues

### Android Analysis Problems

**frida-server Not Found**:
```bash
# Check frida-server location
adb shell find /data/local/tmp -name "*frida*"

# Download and install frida-server
# 1. Check device architecture
adb shell getprop ro.product.cpu.abi

# 2. Download matching frida-server from GitHub releases
# 3. Install frida-server
adb push frida-server-17.0.0-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"
```

**App Crashes on Hook**:
```bash
# Step 0: does the agent even load? (installs no TLS hooks)
fritap -m --probe com.example.app

# Enable anti-root detection bypass
fritap -m --anti_root -k keys.log com.example.app

# Run with debug output persisted to a file
fritap -m -v -do --debug-log ./debug.log -k keys.log com.example.app
```

friTap collects the tombstone and `logcat -b crash` for you and writes them into
that debug log. Work through
[friTap crashes the target application immediately](#fritap-crashes-the-target-application-immediately)
for the full ladder; if the app is PairIP-protected, jump to
[Anti-Tamper / Integrity-Protected Apps (PairIP)](#anti-tamper-integrity-protected-apps-pairip).

**Package Not Found**:
```bash
# List installed packages
frida-ps -Uai

# Check package name
adb shell pm list packages | grep example

# Use exact package name
fritap -m -k keys.log com.example.app.debug
```

### iOS Analysis Problems

**Jailbreak Detection**:

friTap doesn’t include built-in jailbreak-evasion mechanisms—but it allows you to inject your own custom hooks to bypass or disable jailbreak checks in target applications.

Simply write your custom hooking logic (e.g., intercepting calls like isJailbroken() or checking file paths under /private/var/) and pass it to friTap using the
-c
flag:

```bash
fritap \
  -c my_jailbreak_evasion.js \
  --patterns patterns.json \
  -k keys.log \
  target_app

```

A good starting point to develop your own jailbreak bypass you might have a look at the following links:
- https://www.synacktiv.com/sites/default/files/2021-07/Jailbreak_detection-Pass_The_Salt_2021.pdf
- https://codeshare.frida.re/@incogbyte/ios-jailbreak-bypass/
- https://github.com/Incognito-Lab/Frida-iOS-Jailbreak-detection-bypass/blob/main/ios-jailbreak-detection-bypass.js
- https://codeshare.frida.re/@sridharas04/darkprince-jailbreak-detection-bypass/
- https://www.romainthomas.fr/post/21-07-pokemongo-anti-frida-jailbreak-bypass/


!!! note "Why No `--anti_jailbreak` Flag?"
    Unlike the `--anti_root` flag for Android, friTap does not provide a generic jailbreak bypass. Jailbreak detection techniques on iOS are highly varied, often specific to the app and iOS version, making a universal bypass impractical. Instead, friTap provides the flexibility to use custom scripts (`-c`) tailored to the target application.

Your script might patch out a jailbreak-check function like so:

```javascript
// my_jailbreak_evasion.js
//
// Two things matter here:
//   1. Module.getExportByName() THROWS when the symbol is absent. Without the
//      guard below, loading this script kills your friTap session outright.
//   2. The return value is replaced in onLeave. Do not set it in onEnter —
//      onEnter runs before the function has produced a value.
const isJailbroken = Module.findExportByName(null, "isJailbroken");

if (isJailbroken === null) {
    console.log("[!] isJailbroken() not exported here — nothing to patch");
} else {
    Interceptor.attach(isJailbroken, {
        onLeave(retval) {
            console.log("[*] isJailbroken() -> forcing false");
            retval.replace(ptr("0"));
        }
    });
}
```

If the symbol is not exported (the common case for a real app), you have to find
the check yourself — see the references above.

### Rootless jailbreak: frida-server not found (iOS)

**Symptom**: on a **rootless** jailbreak (palera1n, Dopamine) friTap cannot find
or start frida-server, even though `frida-ps -U` works once you start it by hand.

**Cause**: a rootless jailbreak moves the **bootstrap prefix** under `/var/jb`.
So `/usr`, `/etc`, `/bin` and friends are shadowed, and frida-server lives at:

```
/var/jb/usr/sbin/frida-server
```

friTap's TUI server manager hardcodes the **rootful** path
`/usr/local/bin/frida-server` and has no `/var/jb` variant, so it cannot start
the server for you on a rootless device.

**Fix**: start frida-server yourself, then let friTap attach.

```bash
ssh mobile@device-ip
/var/jb/usr/sbin/frida-server -D          # or via your jailbreak's launchd job
```

```bash
# from the host, once the server is up
frida-ps -U
fritap -m -k keys.log com.example.app
```

!!! note "`/var/mobile` does **not** move"
    Only the bootstrap prefix is relocated. User data paths stay where they are —
    in particular crash reports remain at
    `/var/mobile/Library/Logs/CrashReporter` on rootful **and** rootless devices,
    which is where friTap looks for them.

**Code Signing Issues**:
```bash
# Use ldid to re-sign if needed
ldid -S frida-server

# Inspect what a report blamed (friTap decodes this for you on a crash)
# codesigning / CS_INVALID => rejected by AMFI; re-sign with valid entitlements
ldid -e /path/to/binary
```

## Application-Specific Issues

### Browser Issues

**Chrome/Chromium Sandboxing**:
```bash
# Disable sandbox for analysis
google-chrome --no-sandbox --disable-web-security --user-data-dir=/tmp/chrome_test
fritap -k chrome_keys.log google-chrome
```

**Firefox Profile Issues**:
```bash
# Use temporary profile
firefox -profile /tmp/firefox_temp
fritap -k firefox_keys.log firefox
```

### Electron Apps

**Electron Detection Issues**:
```bash
# Target electron process directly
fritap $(pgrep electron) -k keys.log

# Hook the main process AND its renderers/utility children
fritap --enable_child_gating -k keys.log electron_app
```

!!! note "Child gating, not spawn gating"
    Electron renderers are **children of the target**, so
    `--enable_child_gating` is the correct flag. `--enable_spawn_gating` catches
    newly spawned processes matching the *target app name* — an Android
    multi-process-app mechanism that will not pick up Electron's renderers.

### Flutter Applications

**No BoringSSL Detection**:

Flutter statically links BoringSSL into `libflutter.so` with symbols stripped, so
friTap needs a byte pattern for `ssl_log_secret()`. Generate one with
BoringSecretHunter:

```bash
# 1. Build the BoringSecretHunter container
git clone https://github.com/monkeywave/BoringSecretHunter.git
cd BoringSecretHunter
docker build -t boringsecrethunter .

# 2. Create the mount points and drop the target library into ./binary
#    (WITHOUT this step both mounts are empty and the tool finds nothing)
mkdir -p binary results
cp /path/to/libflutter.so binary/

# 3. Run it
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter
```

It prints something like:

```text
Analyzing libflutter.so...
...
Byte pattern for frida (friTap): 3F 23 03 D5 FF C3 01 D1 FD ...
```

Put that pattern into a pattern JSON (see
[Pattern-based hooking](../advanced/patterns.md) for the schema) and pass the
**same filename** to friTap:

```bash
fritap --patterns flutter_patterns.json -k keys.log com.flutter.app
```

!!! note "Extracting `libflutter.so` from the device"
    friTap can pull the library for you, so you have something to put in
    `./binary`:

    ```bash
    fritap -m --extract-libraries ./libs com.flutter.app
    ```

### Anti-Tamper / Integrity-Protected Apps (PairIP)

**Symptom**: the target crashes (`SIGSEGV`) almost immediately after friTap
attaches, while plain `frida -U -f <package>` (no script) does **not** crash it.
friTap prints a warning when it sees the protection:

```
[!!!] ANTI-TAMPER PROTECTION DETECTED: Google PairIP (libpairipcore.so)
  VM-based Play-integrity / anti-tamper; checksums loaded code and self-terminates (SIGSEGV) when it detects an inline hook.
  -> friTap's inline hooks may be detected; the app may crash (SIGSEGV).
  See fkie-cad/friTap#64. There is no in-tool PairIP bypass.
```

**Cause**: Google **PairIP** (`libpairipcore.so`) is a VM-based Play-integrity /
anti-tamper runtime. It runs a periodic in-process code-integrity check and
**self-terminates with a `SIGSEGV`** when it finds an inline hook in a library it
protects. friTap's default footprint — the `android_dlopen_ext` loader
trampoline, `Memory.scan` byte-pattern passes, and Java/ART hooks — trips that
check. Plain `frida -f` patches no code, so it survives.

**Fix — use `--pairip-safe`**: friTap ships a minimal, scan-free Android capture
mode for exactly this case. It hooks only a curated TLS-library allowlist,
resolved **without any `Memory.scan`**, and disables the loader hook, Java hooks,
the WebView/Cronet pattern scan and OHTTP — surviving PairIP's check long enough
to extract keys.

```bash
fritap -m -k keys.log --pairip-safe -v com.example.app
```

See the full guide: **[PairIP-Protected Apps](../advanced/pairip-safe.md)** — it
covers the allowlist, attach vs spawn, deriving offsets for a stripped WebView
login, and why `0 keys` usually means *no catchable traffic* (the app was
network-idle), not a broken hook.

**Status**: `--pairip-safe` is best-effort, not a PairIP bypass. Capture depends
on where the app's TLS lives; libraries outside the allowlist (or without a
supplied offset) are not captured. Research references for full neutralization
(out of scope for friTap): `Solaree/pairipcore`, byterialab's PairIP write-up,
and `httptoolkit/frida-interception-and-unpinning` issue #124.

## Debugging Strategies

### Systematic Debugging Approach

Six steps: **does it load → is it friTap → does it install → does it detect → does
it hook → is there traffic**. Do them in order; each one rules something out.

**Step 0: Does the agent load at all?**
```bash
# Loads the agent, reports the platform branch, installs NO TLS hooks
fritap -m --probe com.example.app
fritap --probe -s firefox
```
A healthy probe prints an `Agent platform report: ...` line and
`Probe complete — no hooks were installed and no data was captured.` If the target
survives here but dies without `--probe`, the problem is **hook installation** —
go to [the crash ladder](#fritap-crashes-the-target-application-immediately). If
friTap exits `2`, your agent bundle is too old — see
[the rebuild rule](#i-edited-agentts-and-nothing-changed-the-rebuild-rule).

**Step 1: Control experiment — friTap, or Frida?**
```bash
# No script at all. If this already fails, friTap is not the problem.
frida -U -f com.example.app
frida -f /path/to/binary
```

**Step 2: Is the agent bundle current?**

Only relevant for a **git checkout** — a PyPI install ships a compiled bundle.

```bash
./dev/compile_agent.sh          # must end with: done. Agent: <N> bytes
grep -n "AGENT_ABI_VERSION" friTap/constants.py
```
friTap logs the loaded bundle's ABI unconditionally at INFO, e.g.
`Agent platform report: linux/x86_64 (target=firefox, agent ABI 2)`. If that ABI
does not match `friTap/constants.py`, you are running stale code.

**Step 3: Basic functionality test**

Note the `-s`: friTap **attaches** by default, so a command line has to be
**spawned** or there is no process to attach to.

```bash
# Spawn mode (-s) is REQUIRED for a command line like this
fritap -s -k test_keys.log "$(which curl) https://httpbin.org/get"

# Verify friTap installation
fritap --version
fritap --help
```

**Step 4: Library detection**
```bash
# Check library detection (log to a file; see the note at the top of this page)
fritap -v --debug-log ./detect.log target_app
grep -i "found\|library\|hook" ./detect.log

# List all libraries — this exits WITHOUT capturing
fritap --list-libraries target_app > libs.txt
```

**Step 5: Hook installation**
```bash
# Enable debug output, persisted by friTap itself
fritap -do -v --debug-log ./debug.log target_app

# Check for hook errors
grep -i "error\|fail\|exception" ./debug.log
```

**Step 6: Traffic generation**
```bash
# Verify network activity (ss is Linux-only; use netstat or lsof elsewhere)
netstat -an | grep :443            # portable
ss -tulpn | grep :443              # Linux only
lsof -i :443                       # macOS / BSD

# Test with a minimal application — again, -s to spawn it
fritap -s -k keys.log "$(which wget) https://example.com"
```

!!! note "Useful environment variables"
    | Variable | Effect |
    | --- | --- |
    | `FRITAP_DEBUG_LOG` | Absolute path for the debug log, instead of `./fritap_debug_<ts>_<pid>.log`. Same as `--debug-log`. |
    | `FRITAP_FORCE_SCAN` | Comma-separated module names that must be pattern-scanned even if friTap thinks a sibling library covers them. **Adds to** any `--force-scan` values rather than replacing them. |
    | `FRITAP_AGENT_BUNDLE` | Absolute path to an agent bundle to load instead of the shipped one. Not ABI-filtered. |

### Debug Information Collection

**System Information**:
```bash
# Collect system info
uname -a > debug_info.txt
cat /etc/os-release >> debug_info.txt
python --version >> debug_info.txt
fritap --version >> debug_info.txt
```

**Process Information**:
```bash
# Target process details
ps aux | grep target_app >> debug_info.txt
lsof -p $(pgrep target_app) >> debug_info.txt
```

**Network Information**:
```bash
# Network connections
netstat -an >> debug_info.txt
ss -tulpn >> debug_info.txt
```

## Getting Help

### Information to Provide

These five items resolve the large majority of friTap reports. The first two are
the ones almost every report omits.

1. **How friTap was installed** — and whether the agent was recompiled:
   - **git checkout** or **`pip install fritap`**? They behave differently.
   - If a git checkout: did you run **`./dev/compile_agent.sh`**, and did it print
     the `done. Agent: <N> bytes` line? An un-recompiled checkout runs stale agent
     code and is the single most common false lead. See
     [the rebuild rule](#i-edited-agentts-and-nothing-changed-the-rebuild-rule).
   - `git rev-parse --short HEAD` for a checkout, `fritap --version` for both.

2. **The agent platform report line**. friTap logs this unconditionally at INFO on
   every run:

   ```
   Agent platform report: android/arm64 (target=com.example.app, agent ABI 2)
   ```

   It names the platform branch the agent picked *and* the loaded bundle's ABI, so
   it answers "which code path ran" and "is the bundle stale" in one line.

3. **System information**:
   - Operating system and version.
     **On macOS/iOS, give `kern.osproductversion`** — that is the value friTap's
     offset code actually reads. `uname -a` reports the *kernel* version (e.g.
     `25.3.0`), which is not usable here:
     ```bash
     sysctl -n kern.osproductversion      # e.g. 26.3.1  <- this one
     uname -m                             # arm64 / x86_64
     ```
   - Python version, friTap version, Frida version (host **and** on-device
     frida-server).
   - **Device and jailbreak/root type** for mobile: model, OS version, and whether
     the jailbreak is **rootful** or **rootless** (palera1n/Dopamine) — the
     frida-server path differs, see
     [Rootless jailbreak](#rootless-jailbreak-frida-server-not-found-ios).

4. **Command used, and the log file** — use `--debug-log`, not a shell pipe:
   ```bash
   fritap -do -v --debug-log ./debug.log -k keys.log target_app
   ```
   `2>&1 | tee debug.log` works, but only captures the console stream;
   `--debug-log` is written by friTap itself and also captures the crash reports
   it collects, which is what makes a bug report actionable.

5. **Target application and error output**:
   - Application name and version; SSL library if known; desktop or mobile.
   - Complete error messages, the debug log, any stack traces.
   - For a crash: the **last hook breadcrumb** friTap reported
     (`agent-init*` vs `install-phase*`) and whether the target survives
     `fritap --probe`.

### Diagnostic Commands

**Complete Diagnostic**:
```bash
#!/bin/bash
# Generate comprehensive diagnostic report

echo "=== friTap Diagnostic Report ===" > diagnostic.txt
echo "Date: $(date)" >> diagnostic.txt
echo "User: $(whoami)" >> diagnostic.txt

echo -e "\n=== System Information ===" >> diagnostic.txt
uname -a >> diagnostic.txt
cat /etc/os-release >> diagnostic.txt 2>/dev/null || sw_vers >> diagnostic.txt 2>/dev/null
# On Apple: the OS product version is what friTap's offset code reads.
sysctl -n kern.osproductversion >> diagnostic.txt 2>/dev/null

echo -e "\n=== Python Environment ===" >> diagnostic.txt
python --version >> diagnostic.txt
pip list | grep -E "(fritap|frida)" >> diagnostic.txt

echo -e "\n=== Install Type / Agent Bundle ===" >> diagnostic.txt
# git checkout or PyPI install? And is the compiled agent in step with the host?
git rev-parse --short HEAD >> diagnostic.txt 2>/dev/null \
  || echo "not a git checkout (PyPI install)" >> diagnostic.txt
grep -n "AGENT_ABI_VERSION" friTap/constants.py >> diagnostic.txt 2>/dev/null
ls -l friTap/fritap_agent.js >> diagnostic.txt 2>/dev/null
echo "FRITAP_AGENT_BUNDLE=${FRITAP_AGENT_BUNDLE:-<unset>}" >> diagnostic.txt

echo -e "\n=== Target Process ===" >> diagnostic.txt
TARGET="$1"
ps aux | grep "$TARGET" >> diagnostic.txt

echo -e "\n=== friTap Test ===" >> diagnostic.txt
fritap --version >> diagnostic.txt
frida-ls-devices >> diagnostic.txt 2>&1
# Dry run: loads the agent, installs no TLS hooks, prints the platform report.
[ -n "$TARGET" ] && fritap --probe "$TARGET" >> diagnostic.txt 2>&1

echo -e "\n=== Network Status ===" >> diagnostic.txt
netstat -an | head -20 >> diagnostic.txt

echo "Diagnostic report saved to diagnostic.txt"
```

### Community Resources

- **GitHub Issues**: [https://github.com/fkie-cad/friTap/issues](https://github.com/fkie-cad/friTap/issues)
- **Discussions**: [https://github.com/fkie-cad/friTap/discussions](https://github.com/fkie-cad/friTap/discussions)
- **Email**: daniel.baier@fkie.fraunhofer.de

### Before Opening Issues

1. **Search existing issues** for similar problems
2. **Try troubleshooting steps** from this guide
3. **Collect diagnostic information** using commands above
4. **Provide minimal reproduction case** if possible
5. **Include all requested information** in issue template

## Next Steps

- **Advanced Debugging**: Use `-do -v --debug-log ./debug.log` for detailed
  diagnostics in a file, and `--probe` to separate agent-load failures from
  hook-install failures. Full flag list: [CLI reference](../api/cli.md).
- **Slow or hanging attach**: raise the agent load bound with
  `--script-load-timeout <seconds>` (default `20.0`, automatically tripled when a
  scan is requested). See
  [CLI reference](../api/cli.md#-script-load-timeout-seconds).
- **Performance Tuning**: Use appropriate output formats and minimize unnecessary
  options; `--quic-only` and `--pairip-safe` give much lighter attaches.
- **Platform Issues**: Review the platform-specific guides —
  [Android](../platforms/android.md), [iOS](../platforms/ios.md),
  [macOS](../platforms/macos.md), [Linux](../platforms/linux.md),
  [Windows](../platforms/windows.md).
- **Integrating the agent yourself**: [Standalone agent](../advanced/standalone-agent.md).
- **Feature Requests**: Visit [GitHub Discussions](https://github.com/fkie-cad/friTap/discussions)