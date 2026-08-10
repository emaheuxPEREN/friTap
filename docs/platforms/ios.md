# iOS Platform Guide

This guide covers iOS-specific setup, considerations, and best practices for using friTap on iOS devices.

!!! warning "iOS is keylog-only"
    On iOS friTap extracts **TLS key material only**. There are no plaintext
    read/write hooks and no working packet capture: `-p/--pcap` produces an
    **empty** pcap file and `-f/--full_capture` is broken (see
    [Packet capture does not work on iOS](#packet-capture-does-not-work-on-ios)).
    The supported workflow is `-k keys.log` plus a pcap you capture separately,
    decrypted together in Wireshark.

    The root cause is that friTap cannot recover the socket file descriptor from
    an `SSL_read`/`SSL_write` on Apple platforms, so it has no 5-tuple to frame
    plaintext with.

## What friTap can and cannot see on iOS

friTap hooks TLS libraries, not Apple's networking APIs. The distinction that
matters is *which TLS implementation* an app ends up in:

| App's TLS path | Keys? | Why |
|---|---|---|
| **Network.framework / CFNetwork / URLSession** | ✅ Yes | These are implemented on top of `/usr/lib/libboringssl.dylib`, which is exactly the module friTap hooks. A Swift `URLSession` client produced 220 well-formed keys attributed to `libboringssl.dylib` (measured on Apple arm64). |
| **`libboringssl.dylib` used directly** | ✅ Yes | Same module, same hook. |
| **Cronet (`*cronet*.dylib`)** | ⚠️ Registered, untested | Ships default arm64 patterns and an `ssl_log_secret` symbol fallback. |
| **Flutter (`*flutter*.dylib`)** | ⚠️ Pattern-based | arm64 patterns only. |
| **SecureTransport (Security.framework) / `libcoretls`** | ❌ No | friTap installs **no hooks** at all there. Verified by code search: zero hits for `nw_connection`, `nw_protocol`, `SecureTransport`, `SSLCreateContext`, `libcoretls`, `CFStream`. |
| **A bundled third-party TLS stack** | ❌ No | Nothing registered for it on iOS. Unless the app ships its own copy of BoringSSL matching one of the module patterns above, there is no hook. |

!!! note "Correcting a common misconception"
    Network.framework and `URLSession` apps **do** yield keys. Only legacy
    **SecureTransport** usage and apps that statically bundle a foreign TLS
    stack are genuinely out of reach.

    Provenance of that claim, stated plainly: the 220-key measurement was taken
    on **macOS**, against a Swift `URLSession` client, because iOS and macOS
    share `/usr/lib/libboringssl.dylib` and CFNetwork routes through it on both.
    Extending it to iOS is an inference from that shared stack, not a
    device-verified result. It is corroborated by a read-only BoringSSL
    keylogger ([jankais3r/Frida-iOS-15-TLS-Keylogger](https://github.com/jankais3r/Frida-iOS-15-TLS-Keylogger))
    working on iOS system apps, which is what friTap's own source cites when
    explaining fkie-cad/friTap#65.

### How key extraction works on iOS

Apple does not export `SSL_CTX_set_keylog_callback`. friTap therefore hooks the
**exported** `SSL_CTX_set_info_callback` and writes its own keylog callback
**directly into the live `SSL_CTX` struct** at a byte offset.

That offset is load-bearing: a wrong value clobbers a neighbouring field and
kills the target process. friTap derives it at run time from the target's own
binary by disassembling the non-exported setter and decoding the immediate in
its two-instruction body:

```text
_SSL_CTX_set_keylog_callback:
    str x1, [x0, #0x310]      ; ctx->keylog_callback = cb
    ret
```

A per-OS-version table is the fallback when that decode is not possible.

!!! warning "iOS caveat: the fallback may in practice be the primary path"
    The run-time decode needs `Module.enumerateSymbols()` to return shared-cache
    **local** symbols. That is verified to work on macOS. On a real iOS device the
    on-device dyld shared cache normally has its local symbols stripped into a
    `.symbols` file that Apple does not ship, so **on iOS the version table is
    plausibly the operative path rather than the fallback**. This has not been
    verified on-device either way. Use `-do` to see which offset was chosen and
    what its provenance was.

## Prerequisites

### Device requirements

- **Jailbroken iOS device.** A jailbreak is genuinely required: the friTap CLI
  has no Frida Gadget / jailed-app code path.
- **arm64 only.** Load-bearing, not incidental: the offset derivation decodes
  arm64 instructions.
- **frida-server** running on the device.
- USB connection (via usbmuxd) or SSH access.

### Checking jailed vs jailbroken

```bash
frida-ps -Uai
```

If this lists your installed applications, frida-server is reachable and the
device is usable. If it errors out or lists nothing, fix that before touching
friTap.

### iOS version support

There is **no version gate anywhere in friTap's code**. What actually varies by
version is the `SSL_CTX.keylog_callback` offset used as fallback:

| iOS version | Offset | Provenance |
|---|---|---|
| **18 and newer** (incl. 26) | `0x310` | Measured from Apple binaries (iOS 18.6 and 26.2 **Simulator** runtimes, not device builds) |
| **17** | `0x308` | Measured from Apple binaries (iOS 17.0 and 17.5 **Simulator** runtimes) |
| **16** | `0x300` | Field-reported: contributed by users who ran it successfully, never re-measured in this repo |
| **15** | `0x2F8` | Field-reported |
| **14** | `0x2B8` | Field-reported |
| **13 and older** | `0x2A8` | Single catch-all, never measured. **Untested.** |

iOS 14 through 26 each have their own bucket. iOS 13 and earlier share one
never-measured value and should be treated as untested.

!!! note "Field-reported is not the same as guessed"
    The iOS 14/15/16 values were contributed by users who ran friTap
    successfully on those releases. They have real-world evidence behind them,
    just not a measurement reproducible in this repository.

### Host machine setup

```bash
# macOS
brew install usbmuxd
brew install libimobiledevice

# Linux
sudo apt install usbmuxd libimobiledevice-tools

# frida tooling
pip3 install frida-tools
```

`libimobiledevice` provides `iproxy` (USB port forwarding) and
`idevicecrashreport`, which friTap uses to pull crash reports after an
instrumented target dies (see [iOS crash reporting](#ios-crash-reporting)).

!!! warning "libimobiledevice is not an installed dependency"
    `libimobiledevice` is declared in **no** friTap dependency file. Install it
    yourself if you want the crash-report path.

## Device Setup

### Jailbreak tools

| Jailbreak | iOS range | Type | Notes |
|---|---|---|---|
| **palera1n** | 15 – 18+ | **rootless** and **rootful** | checkm8-based; the tethered/semi-tethered path covers A11 and earlier |
| **Dopamine** | 15 – 16.6.1 | **rootless** | A12 – A16 |
| **XinaA15** | 15 | rootless | |
| checkra1n | 12.0 – 14.8.1 | rootful | legacy |
| unc0ver | 11.0 – 14.8 | rootful | legacy |
| Taurine | 14.0 – 14.3 | rootful | legacy |
| Odyssey | 13.0 – 13.7 | rootful | legacy |

The four legacy tools all cap out at iOS 14.8.1. friTap carries measured or
field-reported offsets for iOS 17, 18 and 26, so a modern rootless jailbreak is
the normal setup today.

### Rootless jailbreaks

On a rootless jailbreak the entire bootstrap prefix moves under `/var/jb`:

```text
/var/jb/usr/sbin/frida-server     # not /usr/sbin/frida-server
/var/jb/Applications/Sileo.app    # Sileo / Zebra live under the prefix too
```

!!! warning "/var/mobile does NOT move"
    `/var/jb` shadows only the bootstrap prefix (`/usr`, `/etc`, `/Library`, …).
    `/var/mobile` stays where it is, so crash reports remain at
    `/var/mobile/Library/Logs/CrashReporter` on rootless jailbreaks too. This
    asymmetry is documented in `friTap/ios.py`.

!!! warning "friTap's TUI server manager is rootful-only"
    `friTap/server_manager/ios.py` hardcodes `REMOTE_PATH =
    "/usr/local/bin/frida-server"` with no `/var/jb` variant. On a rootless
    jailbreak, **start frida-server yourself** rather than relying on the
    managed deployment. The same manager also assumes SSH over an
    iproxy-forwarded port: `ssh_host="root@localhost"`, `ssh_port=2222`.

### Install Frida on the device

```bash
# Method 1: via Sileo / Zebra / Cydia
#   Add the Frida repository: https://build.frida.re
#   Install the "Frida" package

# Method 2: manual, over SSH
ssh root@<device-ip>
apt update
apt install re.frida.server
```

### SSH setup (optional)

```bash
# Install OpenSSH via Sileo/Zebra/Cydia
# Default credentials (CHANGE IMMEDIATELY):
#   Username: root
#   Password: alpine

ssh root@<device-ip>

# Change the default password before doing anything else
passwd root
```

### USB connection setup

```bash
# Forward the frida-server port over USB.
# Modern libimobiledevice syntax is LOCAL:REMOTE
iproxy 27042:27042

# friTap's own server manager expects SSH on forwarded port 2222
iproxy 2222:22

# Verify
frida-ls-devices
```

!!! note "`iproxy 27042 27042` is deprecated"
    The two-argument form still works on older builds but is deprecated. Use
    `iproxy 27042:27042`.

## Frida Server Management

### Starting frida-server

```bash
# Rootful jailbreak
ssh root@<device-ip>
frida-server &

# Rootless jailbreak (palera1n rootless, Dopamine, XinaA15)
ssh root@<device-ip>
/var/jb/usr/sbin/frida-server &
```

### Verifying server status

```bash
# Devices reachable from the host
frida-ls-devices

# Running processes on the device
frida-ps -U

# Installed applications (bundle identifiers)
frida-ps -Uai
```

!!! note
    `frida-ls-devices` only *lists* devices. It does **not** start frida-server
    on the device.

## friTap Usage on iOS

### Basic analysis

```bash
# The canonical iOS invocation: attach, extract keys
fritap -m -k keys.log com.example.app

# Verbose plus debug output
fritap -m -v -do com.example.app

# Metadata about which libraries were hooked
fritap -m -k keys.log -j metadata.json com.example.app
```

Attach mode is the default. Add `-s/--spawn` only when you need it.

### App identification

```bash
# List running apps
frida-ps -Ua

# List installed apps with bundle identifiers
frida-ps -Uai

# Find a specific app (write to a file first, see the piping note below)
frida-ps -Uai > apps.txt
grep -i instagram apps.txt

# Then target the bundle identifier
fritap -m -k keys.log com.burbn.instagram
```

!!! tip "Redirect to a file rather than piping friTap into `head` or `grep`"
    During a capture friTap writes everything to **stderr**, so a pipe needs
    `2>&1` to see anything. Even then a file is better — it survives the session and can be
    re-searched without re-capturing:

    ```bash
    # Works, but only what scrolls past — and nothing without the 2>&1
    fritap -m -v com.example.app 2>&1 | grep -i ssl

    # Better
    fritap -m -v com.example.app > fritap.log 2>&1
    grep -i ssl fritap.log
    ```

### Spawn mode

```bash
# Start the app fresh under friTap control, capturing startup TLS
fritap -m -s -k keys.log com.example.app
```

Spawn mode gets the keylog hook live before the app resumes, which matters for
TLS that happens during launch. It is **not** a pinning bypass and not a
crash workaround; if a spawn crashes, try attach mode instead (see
[Debugging agent-load crashes](#debugging-agent-load-crashes)).

### Packet capture does not work on iOS

!!! danger "`-p/--pcap` yields an empty file on iOS"
    friTap creates the pcap eagerly at session start and writes the 24-byte
    libpcap file header — then never writes a single packet record, because iOS
    has no plaintext hooks. Any `--pcap` on iOS is misleading output, not data.

!!! danger "Do not use `-f/--full_capture` on iOS"
    It is broken twice over:

    1. friTap errors out if `-f` is given without `-p`.
    2. `friTap/pcap.py` logs `currently a full capture on iOS is not
       supported\nAbborting...` and calls `exit(2)` — which raises `SystemExit`
       inside a thread whose handler only catches `Exception`. friTap therefore
       does **not** abort; it keeps running with a dead capture thread.

**Use this workflow instead:**

```bash
# 1. Capture keys with friTap
fritap -m -k keys.log com.example.app

# 2. Capture packets separately (host-side, upstream router, tcpdump on a
#    gateway, a Wi-Fi capture, etc.) into traffic.pcap

# 3. In Wireshark:
#    Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
#    -> point it at keys.log, then open traffic.pcap
```

## SSL/TLS Libraries on iOS

**Six** TLS libraries are registered for iOS (`agent/platforms/ios.ts`). The
socket library is `libSystem.B.dylib`.

| Library | Module pattern | Support | Mechanism |
|---|---|---|---|
| **BoringSSL** | `/.*libboringssl\.dylib/` | Keys (keylog) | Hooks the exported `SSL_CTX_set_info_callback`, then **writes the keylog callback into the `SSL_CTX` struct** at a derived byte offset. This is Apple's own `/usr/lib/libboringssl.dylib`, not Chrome's bundled copy. |
| **LibreSSL** | versioned `libssl.<n>[.<n>].dylib` at exactly `/usr/lib/` | Keys **+ plaintext**, untested on device | iOS's own shared-cache LibreSSL. Uses the library's own `SSL_CTX_set_keylog_callback` where available, falling back to KDF hooks (`tls1_PRF`, `tls13_hkdf_expand_label`). Shares the macOS implementation. |
| **OpenSSL** | versioned `libssl.<n>[.<n>].dylib` **outside** `/usr/lib/` | Keys **+ plaintext**, untested on device | Genuine OpenSSL bundled inside an app. Calls the library's own keylog setter — no struct-offset write. |
| **OpenSSL/BoringSSL** | `libssl*.dylib` that is **not** a versioned name | Keys | Generic fallback for app-bundled BoringSSL copies named `libssl.dylib` and similar. |
| **Cronet** | `/.*cronet.*\.dylib/` | Keys, untested | Ships default arm64 patterns **and** an `ssl_log_secret` symbol fallback. The code's own word for it is "untested". |
| **Flutter BoringSSL** | `/.*flutter.*\.dylib/` | Keys (keylog) | Pattern-based, arm64 key only. |

There is **no QUIC support on iOS**, and no NSS, GnuTLS, mbedTLS or wolfSSL.

!!! warning "The three `libssl` entries are not device-validated"
    iOS had no `libssl`/LibreSSL entry at all until 2026-08-05, so an app bundling
    OpenSSL — and iOS's own shared-cache LibreSSL — went entirely unhooked. The
    entries now mirror macOS exactly and the **routing** is unit-tested
    (`agent/shared/registry.test.ts`), but the executors themselves have only ever
    run on macOS. Treat keys from these three as unproven on iOS hardware and
    please report results.

    They divide the `libssl*.dylib` name space as a strict partition — see
    [the macOS explanation](macos.md#ssltls-libraries-on-macos), which uses the
    same shared predicates from `agent/shared/darwin_library_patterns.ts`.

!!! note "`--modern` and Cronet"
    `--modern` lists **iOS/macOS Cronet** among its known regressions versus the
    legacy default. For Cronet on iOS, stay on the default (legacy) path.

### Pattern-based hooking on iOS

`--patterns` accepts an `ios` platform key, but be aware:

!!! warning "No shipped iOS patterns"
    `friTap/patterns/default_patterns.json` ships **no `ios` sub-key for any
    library**. Every entry in it is `linux` or `android` only. If you need
    patterns on iOS, you have to supply them yourself.

```bash
# Absolute path recommended
fritap -m --patterns /abs/path/to/ios_patterns.json -k keys.log com.example.app
```

A **missing** `--patterns` file is silently ignored. An **invalid** one warns
and falls back to defaults. Neither case is loud, so verify with `-do` that your
patterns were actually loaded.

### Library detection

```bash
fritap -m -do -v com.example.app > fritap.log 2>&1
grep -i ssl fritap.log
```

With `-j metadata.json`, the `libraries_detected` array lists only libraries
friTap actually hooked. On iOS that means one or more of `BoringSSL`, `LibreSSL`,
`OpenSSL`, `OpenSSL/BoringSSL`, `Cronet`, `Flutter BoringSSL` — nothing else can
ever appear there.

### Limitations

- **No plaintext interception.** Keylog extraction only.
- **Socket FD unavailable.** friTap cannot recover the socket from an
  `SSL_read`/`SSL_write` on Apple, so there is no 5-tuple and no pcap framing.
- **No SecureTransport / `libcoretls` support.** Legacy Security.framework TLS
  is not hooked at all.
- **No QUIC support.**

## Certificate Pinning on iOS

!!! note "Pinning is largely irrelevant to keylog extraction"
    friTap reads key material from **inside** the TLS library. It does not MITM
    the connection, so there is no substitute CA certificate for the app to
    reject. A pinned app negotiates TLS with its real server exactly as it
    normally would, and friTap logs the keys anyway.

friTap has **no certificate-pinning bypass hooks of any kind**. If you need to
intercept *and modify* traffic rather than just decrypt a recording, that is a
proxy job:

```bash
# Redirect connections to a proxy (e.g. mitmproxy).
# Requires the separate fritap-proxy package.
fritap -m --proxy 127.0.0.1:8080 com.example.app
```

Two things that are frequently mistaken for pinning bypasses and are not:

- **`--enable_default_fd` has nothing to do with pinning.** It fabricates a
  placeholder 5-tuple (`127.0.0.1:1234-127.0.0.1:2345`) so pcap framing has
  *something* to write when the socket FD cannot be determined. On iOS, where
  there is no pcap output anyway, it changes nothing useful.
- **Spawn mode (`-s`) is not a bypass.** It only makes hooks live earlier.

## Flags that behave differently on iOS

### `-t/--timeout`

!!! danger "`--timeout` is dangerous on iOS"
    In attach mode `--timeout N` **suspends the target's main thread** for N
    seconds (`friTap/legacy/session_manager.py`). On iOS, freezing an app's main
    thread invites the `0x8badf00d` watchdog kill. It does **not** reduce
    analysis overhead. Avoid it unless you specifically want the target held.

`--timeout` is unrelated to `--script-load-timeout`.

### `--script-load-timeout <seconds>`

Bounds Frida's `script.load()`, i.e. how long friTap waits for the agent to
finish starting up inside the target.

- Default: **20 seconds**.
- **Any non-positive value disables the bound** (`--script-load-timeout 0`).
- Automatically **tripled** when `--patterns`, `--library-scan` or
  `--scan-keys-region` is used, since those scan during agent startup.

!!! note "It is a give-up, not a cancellation"
    `script.load()` is not cancellable. On timeout friTap abandons the load
    thread and reports a diagnostic; the agent may still finish loading inside
    the target afterwards.

### `--offsets`

!!! warning "`--offsets` does not narrow the hook set"
    It supplies **addresses** for functions friTap already intends to hook. It
    never restricts friTap to "specific functions only". On iOS the only useful
    entry is `SSL_CTX_set_info_callback` under an `openssl` key.

### `-c/--custom_script`

!!! warning "Relative paths resolve against the friTap package directory"
    `friTap/plugins/legacy_custom_script.py` resolves a relative
    `--custom_script` path against the **friTap package directory**, not your
    current working directory. A miss is logged once and then skipped at debug
    level, so a typo looks like a script that ran and did nothing. **Always pass
    an absolute path.**

```bash
fritap -m -c /abs/path/to/my_script.js -k keys.log com.example.app
```

### `-do/--debug-output` and `--debug-log`

`-do` enables debug output **and** silently writes
`./fritap_debug_<ts>_<pid>.log` into the current working directory. Use
`--debug-log <path>` to choose the location explicitly.

```bash
fritap -m -do --debug-log /tmp/fritap_ios.log -k keys.log com.example.app
```

## The rebuild rule

!!! danger "friTap runs a pre-compiled agent bundle"
    friTap loads **`friTap/fritap_agent.js`**. Nothing rebuilds `agent/*.ts` at
    run time. **Editing TypeScript changes nothing** until you run:

    ```bash
    ./dev/compile_agent.sh
    ```

    The script writes `frida-compile -o` straight onto the bundle with no temp
    file or backup, so after a **failed** compile what is on disk is undefined —
    possibly the previous bundle, possibly a partial write. Either way the next
    run is not exercising your change, and it looks like the change had no
    effect. The success line is the only positive signal, so always confirm it:

    ```text
    [compile_agent.sh] done. Agent: <bytes> bytes
    ```

    If you do not see that line, the bundle you are about to run is the old one.

### `FRITAP_AGENT_BUNDLE`

This environment variable overrides which bundle gets loaded. It is the clean
A/B lever when you want to compare a modified agent against the shipped one:

```bash
FRITAP_AGENT_BUNDLE=/abs/path/to/my_fritap_agent.js \
    fritap -m -do -k keys.log com.example.app
```

Precedence, highest first:

1. `FRITAP_AGENT_BUNDLE` (**not** ABI-filtered)
2. ABI-matched `fritap.agent_bundle` entry point
3. The shipped bundle

## Debugging agent-load crashes

If the target dies during instrumentation, bisect in this order rather than
guessing.

**(a) `--probe` first.** It loads the agent, reports which platform code path
friTap selected, and installs **no TLS hooks**, producing no keys, pcap or
plaintext.

```bash
fritap -m --probe com.example.app
```

If the target **survives** `--probe`, the agent bootstrap is fine and the crash
is in hook installation.

**(b) Attach instead of spawn.** Drop `-s`:

```bash
fritap -m -k keys.log com.example.app
```

**(c) Try `--modern`.**

```bash
fritap -m --modern -k keys.log com.example.app
```

`--modern` does **not** write into the `SSL_CTX` struct at all. So if the target
**survives** under `--modern` but dies without it, that points at a wrong struct
offset.

!!! note "The signal is asymmetric"
    Surviving under `--modern` is informative. **Dying under it is not**,
    because `--modern` installs hooks of its own that the legacy path does not.

**(d) Collect the diagnostics.**

```bash
fritap -m -do --debug-log /tmp/fritap_ios.log -k keys.log com.example.app
```

Report the printed line:

```text
Agent platform report: <platform> (target=<target>, agent ABI <N>)
```

plus the chosen `SSL_CTX.keylog_callback` offset and its stated provenance.

## iOS crash reporting

When an instrumented target dies, friTap can pull and decode the device's
ReportCrash `.ips` report via `idevicecrashreport` (over usbmuxd, so no
device-side SSH or root shell is needed; reports are pulled with `-k`, keeping
the on-device copy).

Decoded exception types and what they usually mean:

| Signature | Meaning |
|---|---|
| `0x8badf00d` | Watchdog kill — the app was suspended or blocked too long (see the `--timeout` warning above) |
| jetsam | Memory-pressure kill |
| `EXC_BAD_ACCESS` | Usually a **wrong hook offset** |
| `0xdead10cc` | "dead lock" — the app held a file lock or an SQLite database while backgrounded |
| codesigning failures | Signature or entitlement rejection |

!!! warning "This path has never been exercised against a real device"
    Every test of the crash-report code is device-free by construction, and
    `libimobiledevice` is declared in no friTap dependency file. Install it
    yourself with `brew install libimobiledevice` and treat this feature as
    unverified on hardware.

Reports live on the device at `/var/mobile/Library/Logs/CrashReporter`,
including on rootless jailbreaks.

## Reporting an iOS bug

Include all of the following. The first item is the one people get wrong:

- **`kern.osproductversion`**, exactly as printed. This is what the offset code
  reads — not `uname -a`.

  ```bash
  # On the device
  sysctl -n kern.osproductversion
  ```

- The **`Agent platform report:`** line from `-do` output.
- Whether this is a **git checkout or a PyPI install**, and if a checkout,
  **whether you recompiled the agent** (`./dev/compile_agent.sh`, including the
  `done. Agent: <bytes>` line). See [The rebuild rule](#the-rebuild-rule).
- **Jailbreak type**: which tool, and **rootful or rootless**.
- The **`.ips` crash report**, if the target died.
- The exact friTap command line and the target bundle identifier.

## Troubleshooting iOS Issues

### Connection problems

```bash
# Device not detected
frida-ls-devices

# Restart usbmuxd (macOS/Linux)
sudo pkill usbmuxd
sudo usbmuxd

# Restart frida-server on the device
ssh root@<device-ip>
killall frida-server
frida-server &            # rootless: /var/jb/usr/sbin/frida-server &
```

### frida-server issues

```bash
ssh root@<device-ip>
ps aux | grep frida-server

killall frida-server
frida-server &

# Port conflicts
netstat -an | grep 27042
```

### App analysis issues

```bash
# Attach mode is the default when you omit -s/--spawn
fritap -m -k keys.log com.example.app

# Confirm the app is actually running / installed
frida-ps -Uai > apps.txt
grep com.example.app apps.txt
```

If the app crashes when friTap attaches, go to
[Debugging agent-load crashes](#debugging-agent-load-crashes).

### Monitoring device resources

```bash
ssh root@<device-ip>

# Darwin's top filters by user with -U (uppercase)
top -U mobile
```

## iOS-Specific Features

### Background app analysis

```bash
# Catch newly spawned processes matching the target app
fritap -m --enable_spawn_gating -k keys.log com.example.app
```

Then background the app and continue exercising it.

### App extensions

```bash
# Extensions (widgets, keyboards, share sheets) are separate processes
fritap -m -k ext_keys.log com.example.app.extension

# Or catch them as they spawn alongside the host app
fritap -m --enable_spawn_gating -k keys.log com.example.app
```

!!! warning "Spawn gating still needs a target"
    Both `--enable_spawn_gating` and `--spawn_gating_all` require a positional
    target (`nargs="+"`). There is **no "capture everything, no target" mode**.
    Spawn-gating's filter is `identifier.startswith(target_app)`, so it only
    ever catches processes whose identifier begins with what you named.

    Omitting the target makes friTap's argument parser error out — and because
    `ArgParser.error` ends in `exit(0)`, appending `&` will silently background
    a process that does nothing while reporting success. Do not do this.

## Security Considerations

### Device security

- Keep jailbreak tools updated
- **Change the default SSH password** (`root` / `alpine`) immediately
- Use trusted networks for analysis
- Disable services you are not using

### Analysis safety

- Use test accounts for sensitive apps
- Avoid production banking and financial accounts
- Document all analysis activities
- Keep device backups

### Legal considerations

- Only analyze apps you own or have explicit permission to test
- Respect app store terms of service
- Follow responsible disclosure for vulnerabilities you find
- Comply with local laws and regulations

## Wireshark Workflow

Since iOS produces no pcap, decryption is a two-source job: friTap supplies the
keys, something else supplies the packets.

```bash
# 1. Keys from friTap
fritap -m -k keys.log com.example.app

# 2. Packets from anywhere else: a gateway tcpdump, a Wi-Fi capture,
#    an upstream router, a shared-network host capture.

# 3. Wireshark:
#    Preferences -> Protocols -> TLS
#    -> (Pre)-Master-Secret log filename = /path/to/keys.log
#    Then open the pcap.
```

The `keys.log` friTap writes for TLS is in the standard NSS `SSLKEYLOGFILE`
format, so any tool that consumes that format can use it directly.

## Best Practices for iOS Analysis

### 1. Device preparation

- Start from a known-good device state
- Remove artifacts from previous runs
- Confirm frida-server is reachable with `frida-ps -Uai` **before** running friTap

### 2. Analysis methodology

```bash
# Start minimal
fritap -m -k keys.log com.example.app

# Add diagnostics only when something is wrong
fritap -m -v -do --debug-log /tmp/fritap_ios.log -k keys.log com.example.app
```

Do not reach for `--pcap`, `-f`, `--timeout` or `--offsets` on iOS as a matter of
course. Each has an iOS-specific caveat documented above.

### 3. Data management

```bash
mkdir ios_analysis_$(date +%Y%m%d)
cd ios_analysis_$(date +%Y%m%d)

fritap -m -k app_keys.log -j app_metadata.json com.example.app
```

### 4. Documentation

```bash
# Host-side versions
frida --version > device_info.txt

# Device-side OS version — this exact value is what the offset code reads
ssh root@<device-ip> 'sysctl -n kern.osproductversion' >> device_info.txt

# App inventory
frida-ps -Uai > app_info.txt
```

## Common iOS App Categories

!!! note "Expected to work, not tested recipes"
    The commands below are **expected to work** because these apps use
    Network.framework / CFNetwork / `URLSession`, which ride on
    `libboringssl.dylib`. None of them has been verified on a device by this
    project. Bundle identifiers also change between app versions — confirm yours
    with `frida-ps -Uai`.

### Social media apps

```bash
fritap -m -k instagram_keys.log com.burbn.instagram
fritap -m -k twitter_keys.log com.atebits.Tweetie2
fritap -m -k tiktok_keys.log com.zhiliaoapp.musically
```

### Communication apps

```bash
fritap -m -k whatsapp_keys.log net.whatsapp.WhatsApp
fritap -m -k signal_keys.log org.whispersystems.signal
fritap -m -k telegram_keys.log ph.telegra.Telegraph
```

### Financial apps

```bash
# Use test accounts only
fritap -m -k banking_keys.log com.example.bank
fritap -m -k paypal_keys.log com.paypal.ppmobile
```

### Browsers and Chromium-based apps

```bash
# Chrome for iOS bundles Cronet — registered but untested on iOS,
# and a known --modern regression, so stay on the default path
fritap -m -k chrome_keys.log com.google.chrome.ios
```

### Flutter apps

```bash
# Pattern-based, arm64 only
fritap -m -k flutter_keys.log com.example.flutterapp
```

## Next Steps

- **Android Analysis**: Check the [Android Platform Guide](android.md)
- **Desktop Analysis**: See the [Linux](linux.md), [macOS](macos.md) and [Windows](windows.md) guides
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)
