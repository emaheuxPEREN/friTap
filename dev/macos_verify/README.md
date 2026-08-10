# macOS verification rig

A device-free, end-to-end check of friTap's Apple TLS capture path, runnable on
any Apple-silicon Mac.

```bash
./dev/macos_verify/verify.sh            # run every applicable check
./dev/macos_verify/verify.sh --list     # list the checks without running them
./dev/macos_verify/verify.sh --keep     # keep the work dir to inspect raw output
```

Exit code is 0 only if every applicable check passed. Checks that cannot apply
to the current build (for example `--probe` on a build that predates the flag)
are reported as `SKIP`, never silently dropped.

## Why this exists

friTap [discussion #65](https://github.com/fkie-cad/friTap/discussions/65) is an
iOS 16 report: friTap crashes the target immediately, while a standalone Frida
BoringSSL keylogger works. Four separate defects were behind it, and none of
them needed an iOS device to reproduce — because **iOS and macOS share
`/usr/lib/libboringssl.dylib` and the same `SSL_CTX` layout**. That is what
makes this rig a meaningful stand-in for a jailbroken phone:

- the keylog-callback offset is derived from the same two-instruction function
  body on both platforms;
- the spawn-mode bootstrap crash (Foundation messaging in a suspended process)
  reproduces identically;
- the host-side handshake, gating and script-load bugs are platform-independent.

## What it builds

| File | Role |
|---|---|
| `tls_server.py` | Tiny loopback HTTPS server on `127.0.0.1:8443`. No outbound network needed. |
| `tls_client.swift` | URLSession client → CFNetwork → `libboringssl.dylib`, the exact path friTap hooks on Apple platforms. A **fresh ephemeral session per round** forces a new `SSL_CTX` every request, so a wrong offset kills the target within seconds instead of going unnoticed. |
| `tls_fork.swift` | One binary, two roles: run bare it does TLS rounds and `posix_spawn`s a copy of itself with `--child`, so one friTap session must instrument **two** processes. `posix_spawn` (not Foundation's `Process`) is deliberate — it is the syscall Frida's child gating intercepts. The child exits once reparented to launchd, so a killed run never leaks strays. |

The runner generates a throwaway self-signed cert into a temporary work dir on
every run, so nothing here expires or needs refreshing.

## What each check proves

| Check | Proves |
|---|---|
| `repo:unit-tests` | The Python suite CI gates on still passes. |
| `repo:agent-build` | `./dev/compile_agent.sh` succeeds **and is deterministic**. This is the only trustworthy build signal — see the warning below. |
| `capture:attach` | Keys are captured, and every line is well formed. |
| `capture:spawn` | Spawn mode captures **without killing the target** — the failure mode that made #65 look like a friTap crash. |
| `capture:handshake` | Both agent startup handshake stages (`config-handshake`, `anti-handshake`) completed, i.e. the host answered the agent's two blocking `recv().wait()` calls. |
| `timeout:fires` | An unreachable `--script-load-timeout` aborts with an actionable diagnostic instead of hanging forever, and leaves the target running. |
| `timeout:disabled` | `--script-load-timeout 0` really disables the bound. |
| `probe:reports` | `--probe` reports the detected platform **and installs no hooks**. |
| `gating:second-script` | A gated child is instrumented too — two handshake pairs in one session. This is the bug where the second `script.load()` used to hang forever. |

Key files are checked two ways on purpose: line count **and**
`grep -cvE '^[A-Z_0-9]+ [0-9A-F]+ [0-9A-F]+$'` must be 0. A malformed-line
count matters because a past bug read past the NUL terminator and appended heap
garbage, producing a plausible-looking keylog full of unusable keys.

## Requirements

- macOS on Apple silicon (Intel should work, but the offset derivation decodes
  arm64 instructions, so an Intel run exercises the fallback table instead).
- `swiftc` (Xcode command line tools), `openssl`, and a Python with `frida`
  importable — the same environment friTap itself needs.
- **SIP disabled** is normally required for frida to attach to another local
  process. The runner reports SIP status in its preflight and warns rather than
  refusing, so you can see for yourself whether that is what blocked a check.
- No outbound network. Everything is loopback.

## Two traps worth knowing

**The agent bundle is what actually runs.** `friTap/fritap_agent.js` is a
pre-compiled bundle; nothing rebuilds `agent/*.ts` at run time. After any agent
change you must run `./dev/compile_agent.sh` and **confirm the
`done. Agent: <bytes>` line** — that is the only positive signal. The script runs
under `set -euo pipefail` and writes `frida-compile -o` directly onto the bundle
with no temp file or backup, so a failed build leaves *something* undefined on
disk: possibly the previous bundle, possibly a partial write. Either way a test
run afterwards is not exercising the code you just changed. `npx tsc --noEmit` is
*not* a substitute; it has reported the tree clean while `frida-compile`
rejected it.

**Redirect friTap to a file rather than piping it into `head` or `grep`.**
friTap writes to **stderr**, so a pipe needs `2>&1` to see anything, and every
check here greps the same output more than once — which needs a file anyway.
That is what `verify.sh` does throughout.

## Driving it by hand

```bash
WORK=$(mktemp -d)
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 7 -nodes -subj "/CN=localhost"
cp <repo>/dev/macos_verify/tls_server.py .
swiftc -O <repo>/dev/macos_verify/tls_client.swift -o tls_client
python3 tls_server.py & sleep 2
./tls_client & sleep 5

cd <repo>
python -m friTap.friTap -k "$WORK/keys.log" -v -do tls_client   # attach
python -m friTap.friTap -s -k "$WORK/keys.log" -v -do "$WORK/tls_client"   # spawn

wc -l < "$WORK/keys.log"
grep -cvE '^[A-Z_0-9]+ [0-9A-F]+ [0-9A-F]+$' "$WORK/keys.log"   # must be 0
```
