// agent/legacy/tls/shared/apple_keylog_offset.ts
//
// SSL_CTX.keylog_callback field offset for Apple's /usr/lib/libboringssl.dylib,
// and the guarded installer that writes friTap's callback into that field.
//
// WHY A RAW STRUCT WRITE AT ALL
// Apple does not export SSL_CTX_set_keylog_callback: in the simulator runtime
// dylibs it is a LOCAL symbol ('t' in nm output) while SSL_CTX_set_info_callback
// is exported ('T'). friTap therefore hooks the exported set_info_callback and
// writes the callback pointer directly into the SSL_CTX struct. That makes the
// field offset load-bearing — a wrong value silently clobbers a neighbouring
// field (refcount, lock, session-cache pointer) and kills the target process.
// This is what made friTap unusable on iOS while a read-only keylogger such as
// jankais3r/Frida-iOS-15-TLS-Keylogger kept working (fkie-cad/friTap#65).
//
// WHERE THE OFFSET COMES FROM — the target's own binary first, a table second
//
// SSL_CTX_set_keylog_callback is a two-instruction function whose body *is* the
// offset:
//
//   _SSL_CTX_set_keylog_callback:
//     str x1, [x0, #0x310]      <-- ctx->keylog_callback = cb
//     ret
//
// It is not exported, but Frida's Module.enumerateSymbols() DOES return it from
// the dyld shared cache as a local symbol (measured: 4697 symbols on macOS 26,
// including this one). So deriveOffsetFromBinary() decodes the immediate at
// install time and the offset is correct by construction for whatever build the
// target actually loaded — no version knowledge required, self-correcting across
// future OS releases.
//
// The version table below is the FALLBACK for when that symbol is unavailable
// (stripped cache, non-arm64, unexpected function shape). Its values are still
// derived rather than guessed — the iOS Simulator runtimes ship
// /usr/lib/libboringssl.dylib as a standalone file, so:
//
//   nm    -arch arm64 libboringssl.dylib | grep _SSL_CTX_set_keylog_callback
//   otool -arch arm64 -tvV -p _SSL_CTX_set_keylog_callback libboringssl.dylib
//
// yields ground truth. `python dev/derive_boringssl_keylog_offset.py` regenerates
// the table from every installed runtime; `--check` fails on drift.
//
// WHY VALIDATION ALONE WAS NOT ENOUGH (measured, not assumed)
// The installer validates before writing, but that CANNOT establish the offset:
// writing at the stale macOS value 0x2F8 on macOS 26 passes both a writable-range
// check and a NULL-field check — that neighbouring field is also NULL on a fresh
// SSL_CTX — and still kills the target. Hence deriving the offset rather than
// merely guarding the write. The guards remain for what they do catch: an offset
// past the end of the allocation, and a field holding live state.

import { devlog, log } from "../../../util/log.js";
import { ObjC } from "../../../shared/objclib.js";
import { isWritable, isReadable, safeReadPointer, resetReadableCache } from "../../../util/safe_memory.js";
import { isSTRimmU64, isRET, decodeSTRU64Imm, regRd, regRn } from "../../../shared/arm64.js";
import { darwinProductVersion, darwinMajorVersion } from "../../../util/darwin_sysctl.js";

export type ApplePlatform = "iOS" | "MacOS";

/**
 * Where an offset value came from. Surfaced in diagnostics, so the name has to
 * say what it means to someone reading a log line — the earlier labels
 * ("derived" / "legacy") read as a confidence ranking and were mistaken for
 * one, which is exactly the misreading these names avoid.
 *
 * Note that "not measured here" is NOT the same as "unsupported": the
 * field-reported values were contributed by users running friTap on those
 * releases, so they have real-world evidence behind them — just not a
 * measurement reproducible in this repo.
 */
type Provenance =
    // Decoded from THIS target's own libboringssl at run time. Correct by
    // construction for the build being instrumented.
    | "measured-on-target"
    // Read out of a real Apple binary (an iOS Simulator runtime) with nm+otool
    // at development time — a measurement, but of a different copy.
    | "measured-from-apple-binary"
    // Assumed equal to the iOS release of the same year; never measured on
    // macOS itself.
    | "inferred-from-ios-twin"
    // Contributed by users who ran friTap successfully on that release. Working
    // evidence from the field, never re-measured in this repo.
    | "field-reported";

interface OffsetBucket {
    /** Applies to this OS major version and every later one, until a higher bucket matches. */
    minMajor: number;
    offset: number;
    provenance: Provenance;
    note: string;
}

// Ordered high-to-low; the first bucket whose minMajor <= major wins. Keyed on
// OS MAJOR version, and the top bucket is deliberately open-ended.
//
// That shape is the fix for what actually broke here (fkie-cad/friTap#65): the
// old ladders selected on kCFCoreFoundationVersionNumber with every branch
// UPPER-bounded, so once a release shipped with a CF number past the last known
// boundary it fell into the final `else if` no matter which OS it really was.
// The values themselves were not the problem — routing a device away from its
// own bucket was. Major-version buckets with an open top cannot fall through.
const IOS_OFFSETS: OffsetBucket[] = [
    { minMajor: 18, offset: 0x310, provenance: "measured-from-apple-binary", note: "iOS 18.6 + 26.2 simulator runtimes" },
    { minMajor: 17, offset: 0x308, provenance: "measured-from-apple-binary", note: "iOS 17.0 + 17.5 simulator runtimes" },
    { minMajor: 16, offset: 0x300, provenance: "field-reported",             note: "contributed in 2be00c64; worked in the field, not re-measured here" },
    { minMajor: 15, offset: 0x2F8, provenance: "field-reported",             note: "contributed in 22386f56; worked in the field, not re-measured here" },
    { minMajor: 14, offset: 0x2B8, provenance: "field-reported",             note: "contributed in 22386f56; worked in the field, not re-measured here" },
    { minMajor: 0,  offset: 0x2A8, provenance: "field-reported",             note: "original codeshare value, iOS < 14" },
];

// macOS ships the same libboringssl revision as the iOS release of the same
// year, so each bucket is matched to its iOS twin: macOS 26 <-> iOS 26,
// 15 (Sequoia) <-> iOS 18, 14 (Sonoma) <-> iOS 17, 13 (Ventura) <-> iOS 16,
// 12 (Monterey) <-> iOS 15, 11 (Big Sur) <-> iOS 14.
// NOTE: the pre-existing macOS ladder's TOP branch regressed to 0x2F8 — a value
// already used two steps earlier — where every other step increased. macOS 26
// landed there and the resulting write killed the target (measured). These are
// now aligned to the iOS numbers rather than maintained separately.
const MACOS_OFFSETS: OffsetBucket[] = [
    { minMajor: 15, offset: 0x310, provenance: "inferred-from-ios-twin", note: "matches measured iOS 18/26 value; confirmed by live derivation on macOS 26.3.1" },
    { minMajor: 14, offset: 0x308, provenance: "inferred-from-ios-twin", note: "matches measured iOS 17 value" },
    { minMajor: 13, offset: 0x300, provenance: "inferred-from-ios-twin", note: "matches iOS 16 bucket" },
    { minMajor: 12, offset: 0x2F8, provenance: "inferred-from-ios-twin", note: "matches iOS 15 bucket" },
    { minMajor: 11, offset: 0x2B8, provenance: "inferred-from-ios-twin", note: "matches iOS 14 bucket" },
    { minMajor: 0,  offset: 0x2A8, provenance: "field-reported",         note: "original codeshare value" },
];

/**
 * Which source reported the OS major version, listed in the order
 * detectMajorVersion() tries them. Surfaced in every diagnostic line, so a reader
 * needs to be able to tell "the OS told us" from "we guessed from a CF number".
 */
type VersionSource =
    // kern.osproductversion via sysctlbyname. PRIMARY, and the only source that is
    // safe in a spawned, not-yet-resumed process (fkie-cad/friTap#65).
    | "sysctl"
    // -[NSProcessInfo operatingSystemVersionString]. Accurate, but messaging
    // Foundation kills a suspended spawn, so it runs only after sysctl failed.
    | "NSProcessInfo"
    // kCFCoreFoundationVersionNumber, bucketed by coreFoundationVersionToMajor().
    // Coarse, and cannot name a release past the iOS-17 era.
    | "CoreFoundation"
    // Nothing answered: major is -1 and the oldest, most conservative bucket wins.
    | "unknown";

export interface ResolvedKeylogOffset {
    offset: number;
    major: number;
    provenance: Provenance;
    /** Which source reported `major` — sysctl is the primary one; see VersionSource. */
    versionSource: VersionSource;
    /** Human-readable version detail for diagnostics. */
    versionDetail: string;
    note: string;
}

/**
 * Read kCFCoreFoundationVersionNumber, or null when CoreFoundation is absent or
 * the symbol cannot be resolved. Uses findExportByName rather than
 * getExportByName because the latter THROWS on a miss in Frida 17 — the previous
 * `getExportByName(...)?.readDouble()` could never yield undefined and its
 * "iOS < 14" fallback branch was therefore dead code.
 */
function readCoreFoundationVersion(): number | null {
    try {
        const cf = Process.findModuleByName("CoreFoundation");
        if (cf === null) return null;
        const sym = cf.findExportByName("kCFCoreFoundationVersionNumber");
        if (sym === null || sym.isNull()) return null;
        return sym.readDouble();
    } catch (e) {
        return null;
    }
}

/**
 * Coarse kCFCoreFoundationVersionNumber -> OS major mapping. Last resort only —
 * reached when neither sysctl nor NSProcessInfo could answer.
 *
 * The boundaries AND their version attribution are taken verbatim from the two
 * pre-refactor ladders (openssl_boringssl_ios.ts / openssl_boringssl_macos.ts),
 * which used identical CF thresholds and identical version labels:
 *
 *     undefined / < 1751.108     -> "< 14"    0x2A8
 *     >= 1751.108 && < 1854      -> ">= 14"   0x2B8
 *     >= 1854     && < 1946.102  -> ">= 15"   0x2F8
 *     >= 1946.102 && <= 1979.1   -> ">= 16"   0x300
 *     > 1979.1                   -> ">= 17"   0x308 (iOS) / 0x2F8 (macOS)
 *
 * So 1854 opens the 15 window and 1946.102 opens the *16* window. An earlier
 * version of this function started at `cf >= 1946.102 -> 17` and shifted every
 * bucket below it up by one, which handed an iOS 16 device 0x308 where 0x300 is
 * correct.
 *
 * 17 is the highest major this tier can claim, because no CF boundary above
 * 1979.1 is known — Apple stopped publishing the constants long ago. That is a
 * limit of the input, NOT the historical routing error returning. That error was
 * an OPEN `> 1979.1` catch-all which was the SOLE offset selector, so it froze
 * every later release onto one value (measured: iOS 18.6/26.2 store at 0x310
 * while that branch returned 0x308; macOS 26 got 0x2F8 where 0x310 was correct).
 * Here the return value is only an INDEX into the open-topped major buckets
 * above, and it is reached only behind deriveOffsetFromBinary() and behind two
 * sources that report the major directly. (Whether a shipped iOS 16.x point
 * release ever crossed the inclusive 1979.1 cap is UNVERIFIED — no claim either
 * way is made or relied on here.)
 *
 * KNOWN LIMITATION, inherited rather than introduced: CF numbers are per-OS-
 * family while the majors returned here are iOS-family, and MACOS_OFFSETS is
 * keyed on macOS majors (macOS 13 <-> iOS 16), so a macOS host reaching this
 * tier indexes the macOS table too high. The old macOS ladder had the mirror
 * image of that defect — it applied the iOS CF boundaries directly to macOS
 * offsets — so this is not a regression, and it is one more reason this path
 * ranks last.
 */
function coreFoundationVersionToMajor(cf: number): number {
    if (cf > 1979.1) return 17;
    if (cf >= 1946.102) return 16;
    if (cf >= 1854) return 15;
    if (cf >= 1751.108) return 14;
    return 13;   // pre-iOS-14; selects the 0x2A8 bucket, matching the old default
}

/**
 * Detect the OS major version.
 *
 * sysctl FIRST, deliberately. Asking Foundation
 * (`-[NSProcessInfo operatingSystemVersionString]`) kills a spawned, not-yet-resumed
 * process — measured on macOS 26, and the cause of friTap killing every spawned
 * Apple target before installing a hook (fkie-cad/friTap#65). Hook installation runs
 * inside that same pre-resume window in spawn mode, so this function must not
 * message Foundation on the primary path.
 */
function detectMajorVersion(): { major: number; source: VersionSource; detail: string } {
    const sysctlVersion = darwinProductVersion();
    if (sysctlVersion !== null) {
        const major = darwinMajorVersion();
        if (major > 0) {
            return { major, source: "sysctl", detail: `kern.osproductversion=${sysctlVersion}` };
        }
    }

    try {
        if (ObjC.available && ObjC.classes.NSProcessInfo !== undefined) {
            // e.g. "Version 16.7.10 (Build 20H350)" -> 16
            const versionString = ObjC.classes.NSProcessInfo.processInfo()
                .operatingSystemVersionString().toString();
            const matched = versionString.match(/(\d+)\.(\d+)/);
            if (matched !== null) {
                return { major: parseInt(matched[1], 10), source: "NSProcessInfo", detail: versionString };
            }
        }
    } catch (e) {
        // Fall through to CoreFoundation below.
    }

    const cf = readCoreFoundationVersion();
    if (cf !== null) {
        return {
            major: coreFoundationVersionToMajor(cf),
            source: "CoreFoundation",
            detail: `kCFCoreFoundationVersionNumber=${cf}`,
        };
    }

    return { major: -1, source: "unknown", detail: "no version source available" };
}

/**
 * Decode the SSL_CTX.keylog_callback offset out of the TARGET'S OWN binary.
 *
 * `SSL_CTX_set_keylog_callback` is not exported, but Frida's enumerateSymbols()
 * does return it from the dyld shared cache as a local symbol, and the whole
 * function is two instructions:
 *
 *     str x1, [x0, #OFFSET]     <-- ctx->keylog_callback = cb
 *     ret
 *
 * so the immediate IS the offset for exactly this build. This makes the version
 * table below a fallback rather than the source of truth, and removes the entire
 * class of "table went stale and we corrupted the struct" failure.
 *
 * Returns null unless every check passes, because a wrong answer here is fatal:
 *   - the decoder is first validated against the EXPORTED SSL_CTX_set_info_callback,
 *     which has the identical two-instruction shape, so we never trust a decode on
 *     a binary that does not look the way we expect (different arch, thunked
 *     symbol, interposed function);
 *   - the keylog setter must decode as STR x1, [x0, #imm] followed by RET;
 *   - the decoded displacement must be plausible for an SSL_CTX field. imm12 can
 *     encode up to 32760, and writing a function pointer that far out would be
 *     catastrophic, so an absurd decode is rejected rather than trusted. The
 *     observed real values span 0x188 (info_callback) to 0x310 (keylog on iOS 18+),
 *     so the bound is deliberately loose — it only excludes nonsense.
 */
const MIN_PLAUSIBLE_CTX_FIELD_OFFSET = 0x80;
const MAX_PLAUSIBLE_CTX_FIELD_OFFSET = 0x1000;

function deriveOffsetFromBinary(moduleName: string): number | null {
    if (Process.arch !== "arm64") return null;   // only the AArch64 encoding is decoded
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod === null) return null;
        resetReadableCache();   // ranges can have changed since any earlier walk

        // Two-instruction setter body -> the stored field offset, or null.
        // Reads are range-checked first: this runs at install time rather than
        // inside an Interceptor callback, but a native fault is fatal either way,
        // and enumerateSymbols() can hand back addresses that are not mapped (it
        // reports undefined imports at 0x0, for instance).
        const decodeSetter = (addr: NativePointer | null): number | null => {
            if (addr === null || addr.isNull()) return null;
            if (!isReadable(addr, 8)) return null;
            const body = addr.readU32();
            if (!isSTRimmU64(body)) return null;
            if (regRd(body) !== 1 || regRn(body) !== 0) return null;   // STR x1, [x0, ...]
            if (!isRET(addr.add(4).readU32())) return null;
            const offset = decodeSTRU64Imm(body);
            if (offset < MIN_PLAUSIBLE_CTX_FIELD_OFFSET || offset > MAX_PLAUSIBLE_CTX_FIELD_OFFSET) return null;
            return offset;
        };

        // Calibrate: the exported info-callback setter must decode cleanly first.
        if (decodeSetter(mod.findExportByName("SSL_CTX_set_info_callback")) === null) {
            devlog(`[${moduleName}] setter decode calibration failed — not deriving the keylog offset`);
            return null;
        }

        // enumerateSymbols() also yields non-global symbols; match with or without
        // the Mach-O leading underscore.
        for (const sym of mod.enumerateSymbols()) {
            if (sym.name !== "SSL_CTX_set_keylog_callback" && sym.name !== "_SSL_CTX_set_keylog_callback") continue;
            const offset = decodeSetter(sym.address);
            if (offset !== null) return offset;
            devlog(`[${moduleName}] found SSL_CTX_set_keylog_callback but its body is not the expected setter shape`);
            return null;
        }
        return null;
    } catch (e) {
        devlog(`[${moduleName}] keylog offset derivation failed: ${e}`);
        return null;
    }
}

/**
 * Pick the SSL_CTX.keylog_callback offset: prefer the value decoded from the
 * target's own binary, fall back to the version table.
 */
export function resolveKeylogCallbackOffset(platform: ApplePlatform, moduleName?: string): ResolvedKeylogOffset {
    const table = platform === "iOS" ? IOS_OFFSETS : MACOS_OFFSETS;
    const detected = detectMajorVersion();

    if (moduleName !== undefined) {
        const selfDerived = deriveOffsetFromBinary(moduleName);
        if (selfDerived !== null) {
            return {
                offset: selfDerived,
                major: detected.major,
                provenance: "measured-on-target",
                versionSource: detected.source,
                versionDetail: detected.detail,
                note: `decoded from ${moduleName}!SSL_CTX_set_keylog_callback`,
            };
        }
    }
    // major === -1 (no version source) falls into the last bucket, which is the
    // oldest/most conservative value; the install-time check vetoes it if wrong.
    const bucket = table.find(b => detected.major >= b.minMajor) ?? table[table.length - 1];
    return {
        offset: bucket.offset,
        major: detected.major,
        provenance: bucket.provenance,
        versionSource: detected.source,
        versionDetail: detected.detail,
        note: bucket.note,
    };
}

function hex(value: number): string {
    return "0x" + value.toString(16).toUpperCase();
}

/**
 * Hook SSL_CTX_set_info_callback and install friTap's keylog callback into the
 * SSL_CTX struct, but only after proving the target field is safe to write.
 *
 * Three guards, in order:
 *   1. the computed address must sit in a mapped, WRITABLE range — otherwise the
 *      offset ran past the end of the allocation and writePointer() would
 *      SIGSEGV inside the Interceptor callback (which no JS try/catch can save);
 *   2. the field must currently read as NULL — a live pointer or refcount there
 *      proves the offset is wrong;
 *   3. a field already holding OUR callback means we are seeing a second
 *      set_info_callback call on the same context: nothing to do.
 *
 * IMPORTANT — guard 2 is necessary but NOT sufficient, and was measured to be so:
 * writing at the stale macOS offset 0x2F8 on macOS 26 passes both guards (that
 * neighbouring field is also NULL on a fresh SSL_CTX) and still kills the target.
 * Validation alone cannot establish the offset — that is why the offset is now
 * decoded from the target's own binary (deriveOffsetFromBinary) and the table is
 * only a fallback. The guards remain as a net for the cases they DO catch: an
 * offset past the end of the allocation, and a field holding live state.
 *
 * Diagnostics are emitted once (per outcome) rather than per handshake.
 */
export function installKeylogCallbackViaCtxWrite(
    setInfoCallbackAddress: NativePointer,
    keylogCallback: NativePointer,
    platform: ApplePlatform,
    moduleName?: string,
): ResolvedKeylogOffset {
    const resolved = resolveKeylogCallbackOffset(platform, moduleName);

    devlog(
        `[${platform}] SSL_CTX.keylog_callback offset ${hex(resolved.offset)} ` +
        `(OS major ${resolved.major} via ${resolved.versionSource}: ${resolved.versionDetail}; ` +
        `provenance ${resolved.provenance} — ${resolved.note})`,
    );

    let installedOnce = false;
    let vetoedOnce = false;

    Interceptor.attach(setInfoCallbackAddress, {
        onEnter(args: any) {
            try {
                const ctx = ptr(args[0]);
                if (ctx.isNull()) return;

                const target = ctx.add(resolved.offset);

                if (!isWritable(target, Process.pointerSize)) {
                    if (!vetoedOnce) {
                        vetoedOnce = true;
                        log(`[-] ${platform}: refusing to install the BoringSSL keylog callback — ` +
                            `SSL_CTX+${hex(resolved.offset)} is not in a writable mapping.`);
                        log(`[-] The keylog_callback offset for this OS is wrong (detected OS major ` +
                            `${resolved.major} via ${resolved.versionSource}: ${resolved.versionDetail}, ` +
                            `offset provenance: ${resolved.provenance}). No TLS keys will be extracted.`);
                        log(`[-] Please report this with your exact OS version at ` +
                            `https://github.com/fkie-cad/friTap/issues — and run ` +
                            `'python dev/derive_boringssl_keylog_offset.py' if you have Xcode installed.`);
                    }
                    return;
                }

                const current = safeReadPointer(target);
                if (current === null) {
                    if (!vetoedOnce) {
                        vetoedOnce = true;
                        log(`[-] ${platform}: SSL_CTX+${hex(resolved.offset)} became unreadable — ` +
                            `skipping the keylog callback install.`);
                    }
                    return;
                }

                if (current.equals(keylogCallback)) return;  // already installed on this context

                if (!current.isNull()) {
                    if (!vetoedOnce) {
                        vetoedOnce = true;
                        log(`[-] ${platform}: refusing to overwrite SSL_CTX+${hex(resolved.offset)} — ` +
                            `it already holds ${current}, so this is not an empty keylog_callback field.`);
                        log(`[-] Writing there would corrupt BoringSSL's own state and crash the target ` +
                            `(fkie-cad/friTap#65). Detected OS major ${resolved.major} via ` +
                            `${resolved.versionSource}: ${resolved.versionDetail}; offset provenance: ` +
                            `${resolved.provenance}. No TLS keys will be extracted.`);
                        log(`[-] Please report your exact OS version at ` +
                            `https://github.com/fkie-cad/friTap/issues so the offset table can be fixed.`);
                    }
                    return;
                }

                target.writePointer(keylogCallback);
                if (!installedOnce) {
                    installedOnce = true;
                    devlog(`[${platform}] installed BoringSSL keylog callback at SSL_CTX+${hex(resolved.offset)}`);
                }
            } catch (e) {
                if (!vetoedOnce) {
                    vetoedOnce = true;
                    log(`[-] ${platform}: keylog callback install failed: ${e}`);
                }
            }
        },
    });

    return resolved;
}
