// Unit tests for Apple SSL_CTX.keylog_callback offset resolution
// (apple_keylog_offset.ts).
//
// Run: npm run test:agent
//
// Why this exists: friTap writes its keylog callback pointer directly into the
// SSL_CTX struct because Apple does not export SSL_CTX_set_keylog_callback. A
// wrong offset corrupts a neighbouring field and kills the target process
// (fkie-cad/friTap#65).
//
// Two mechanisms are pinned here, in priority order:
//   1. SELF-DERIVATION — decode the immediate out of the target's own
//      SSL_CTX_set_keylog_callback body (`str x1, [x0, #imm]; ret`), reached via
//      enumerateSymbols() even though the symbol is not exported. Correct by
//      construction, so a stale table cannot cause a bad write. Verified
//      end-to-end on macOS by sabotaging every table bucket to the fatal value.
//   2. The VERSION TABLE fallback, whose values come from Apple's binaries
//      (`otool -arch arm64 -tvV -p _SSL_CTX_set_keylog_callback`;
//      `python dev/derive_boringssl_keylog_offset.py` regenerates them). Pinned so
//      a future edit cannot reintroduce the drift that broke iOS — the old ladder
//      capped its newest bucket, so any OS past the cap fell through to a
//      neighbouring offset.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/ObjC/etc. BEFORE the module under test loads.
import "../../../shared/frida-test-stubs.js";
import { resolveKeylogCallbackOffset } from "./apple_keylog_offset.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

/** Make NSProcessInfo report `versionString`, as Foundation would. */
function stubOSVersion(versionString: string): void {
    G.ObjC.available = true;
    G.ObjC.classes = {
        NSProcessInfo: {
            processInfo: () => ({
                operatingSystemVersionString: () => ({ toString: () => versionString }),
            }),
        },
    };
}

/** Remove any stubbed libboringssl so table-only resolution is exercised. */
function stubNoModule(): void {
    G.Process.findModuleByName = () => null;
}

/** Remove every version source, as on a target where ObjC is not up yet. */
function stubNoVersionSource(): void {
    G.ObjC.available = false;
    G.ObjC.classes = {};
    G.Process.findModuleByName = () => null;
}

/**
 * Present a module whose SSL_CTX_set_keylog_callback body stores at `offset`,
 * so resolution can decode it instead of consulting the version table.
 */
function stubLibboringssl(
    offset: number,
    opts: { exportedSetterOk?: boolean; symbolPresent?: boolean; mapped?: boolean } = {},
): void {
    const { exportedSetterOk = true, symbolPresent = true, mapped = true } = opts;
    // STR (immediate, unsigned offset, 64-bit) scales imm12 by 8, so it can only
    // encode multiples of 8. `(imm / 8) << 10` would silently TRUNCATE anything
    // else and stub a different offset than the caller asked for — a test that
    // then asserts against a number the fixture never encoded. Reject it loudly.
    const word = (imm: number) => {
        assert.equal(imm % 8, 0, `offset 0x${imm.toString(16)} is not encodable: STR imm12 scales by 8`);
        return (0xf9000000 | ((imm / 8) << 10) | (0 << 5) | 1) >>> 0;  // str x1,[x0,#imm]
    };
    const RET = 0xd65f03c0;
    const body = (imm: number) => ({
        isNull: () => false,
        and: function () { return this; },
        compare: () => 0,
        readU32: () => word(imm),
        add: (_n: number) => ({ readU32: () => RET, isNull: () => false, and: function () { return this; }, compare: () => 0 }),
    });
    // isReadable() consults Process.findRangeByAddress before any dereference.
    G.Process.findRangeByAddress = () =>
        (mapped ? { base: { compare: () => -1, add: () => ({ compare: () => 1 }) }, size: 0x1000, protection: "r-x" } : null);
    G.Process.arch = "arm64";
    G.Process.findModuleByName = (name: string) => {
        if (name !== "libboringssl.dylib") return null;
        return {
            // Calibration target: the exported info-callback setter.
            findExportByName: (_n: string) => (exportedSetterOk ? body(0x188) : { isNull: () => false, readU32: () => 0xd503201f, add: () => ({ readU32: () => 0 }) }),
            enumerateSymbols: () => (symbolPresent
                ? [{ name: "_SSL_CTX_set_keylog_callback", address: body(offset), isGlobal: false }]
                : [{ name: "_some_other_symbol", address: body(offset), isGlobal: false }]),
        };
    };
}

test("self-derivation from the target binary WINS over the version table", () => {
    // The whole point of the deeper fix: even a stale/wrong table cannot make us
    // write at the wrong offset when the binary tells us the truth. Verified
    // end-to-end on macOS by sabotaging every table bucket to the fatal 0x2F8.
    stubOSVersion("Version 26.3.1 (Build 25D771280a)");
    stubLibboringssl(0x310);
    const resolved = resolveKeylogCallbackOffset("MacOS", "libboringssl.dylib");
    assert.equal(resolved.offset, 0x310);
    assert.equal(resolved.provenance, "measured-on-target");
});

test("self-derivation reports whatever the binary says, table notwithstanding", () => {
    // A hypothetical future OS with a moved field must be followed, not overridden.
    stubOSVersion("Version 27.0 (Build X)");
    stubLibboringssl(0x328);
    assert.equal(resolveKeylogCallbackOffset("iOS", "libboringssl.dylib").offset, 0x328);
});

test("falls back to the table when the local symbol is absent (stripped cache)", () => {
    stubOSVersion("Version 18.6 (Build 22G86)");
    stubLibboringssl(0x999, { symbolPresent: false });
    const resolved = resolveKeylogCallbackOffset("iOS", "libboringssl.dylib");
    assert.equal(resolved.offset, 0x310);          // from the table, not the bogus stub
    assert.equal(resolved.provenance, "measured-from-apple-binary");
});

test("refuses to derive when the decoder cannot be calibrated on the exported setter", () => {
    // Guards against trusting a decode on an unexpected binary shape (wrong arch,
    // thunked or interposed symbol).
    stubOSVersion("Version 18.6 (Build 22G86)");
    stubLibboringssl(0x999, { exportedSetterOk: false });
    const resolved = resolveKeylogCallbackOffset("iOS", "libboringssl.dylib");
    assert.equal(resolved.offset, 0x310);
    assert.notEqual(resolved.provenance, "measured-on-target");
});

test("rejects an implausible decoded offset instead of writing far out of the struct", () => {
    // imm12 can encode up to 32760. A decode that large is nonsense for an
    // SSL_CTX field, and writing a function pointer there would be catastrophic.
    stubOSVersion("Version 18.6 (Build 22G86)");
    stubLibboringssl(0x7000);
    const resolved = resolveKeylogCallbackOffset("iOS", "libboringssl.dylib");
    assert.notEqual(resolved.provenance, "measured-on-target");
    assert.equal(resolved.offset, 0x310);   // fell back to the table
});

test("does not dereference a symbol address that is not mapped", () => {
    // enumerateSymbols() can report addresses that are not readable (it lists
    // undefined imports at 0x0). A native fault here would kill the target even
    // though this runs at install time, so reads are range-checked first.
    stubOSVersion("Version 18.6 (Build 22G86)");
    stubLibboringssl(0x310, { mapped: false });
    const resolved = resolveKeylogCallbackOffset("iOS", "libboringssl.dylib");
    assert.notEqual(resolved.provenance, "measured-on-target");
    assert.equal(resolved.offset, 0x310);
});

test("no derivation is attempted off arm64", () => {
    stubOSVersion("Version 26.3.1 (Build X)");
    stubLibboringssl(0x328);
    G.Process.arch = "x64";
    const resolved = resolveKeylogCallbackOffset("MacOS", "libboringssl.dylib");
    assert.notEqual(resolved.provenance, "measured-on-target");
    G.Process.arch = "arm64";
});

test("derived iOS offsets: 17.x -> 0x308, 18.x and later -> 0x310", () => {
    stubNoModule();
    // Ground truth from the iOS 17.0/17.5 and iOS 18.6/26.2 simulator runtimes.
    const expected: Array<[string, number]> = [
        ["Version 17.0 (Build 21A328)", 0x308],
        ["Version 17.5.1 (Build 21F90)", 0x308],
        ["Version 18.6 (Build 22G86)", 0x310],
        ["Version 26.2 (Build 23C54)", 0x310],
    ];
    for (const [versionString, offset] of expected) {
        stubOSVersion(versionString);
        const resolved = resolveKeylogCallbackOffset("iOS");
        assert.equal(resolved.offset, offset, `wrong offset for ${versionString}`);
        assert.equal(resolved.versionSource, "NSProcessInfo");
    }
});

test("the newest bucket is open-ended — no future release falls through", () => {
    stubNoModule();
    // The pre-fix ladder pinned every release from the iOS-17 era onward to one
    // frozen offset via an open `foundationNumber > 1979.1` catch-all — measured:
    // iOS 18.6 and 26.2 really store at 0x310 while that branch handed out 0x308.
    // (An earlier version of this comment claimed a shipped iOS 16.x point release
    // exceeded the 1979.1 cap and took the iOS-17 branch. That is plausible but
    // UNVERIFIED — Apple stopped publishing the kCFCoreFoundationVersionNumber
    // constants after iOS 9, and no iOS 16 runtime was available to measure.)
    // Either way, nothing may fall through now, however far ahead the version is.
    for (const versionString of ["Version 27.0 (Build X)", "Version 99.9 (Build Y)"]) {
        stubOSVersion(versionString);
        assert.equal(resolveKeylogCallbackOffset("iOS").offset, 0x310, versionString);
    }
});

test("iOS 16.x resolves to one offset for every point release", () => {
    stubNoModule();
    // The reporter of #65 was on iOS 16.x; the old cap split 16.x across two
    // buckets depending on the point release. Every 16.x must agree now.
    const offsets = new Set<number>();
    for (const v of ["Version 16.0 (Build A)", "Version 16.4 (Build B)", "Version 16.7.10 (Build 20H350)"]) {
        stubOSVersion(v);
        offsets.add(resolveKeylogCallbackOffset("iOS").offset);
    }
    assert.equal(offsets.size, 1, `iOS 16.x split across offsets: ${[...offsets].map(o => "0x" + o.toString(16))}`);
});

test("macOS buckets are matched to their iOS twins", () => {
    stubNoModule();
    // macOS ships the same libboringssl revision as the iOS release of the same
    // year. The pre-fix macOS table disagreed with iOS for the same era (0x2F8
    // where iOS used 0x308 — it decreased where iOS increased).
    const pairs: Array<[string, string]> = [
        ["Version 14.7 (Build A)", "Version 17.0 (Build B)"],   // Sonoma  <-> iOS 17
        ["Version 15.1 (Build C)", "Version 18.6 (Build D)"],   // Sequoia <-> iOS 18
        ["Version 26.3.1 (Build E)", "Version 26.2 (Build F)"], // Tahoe   <-> iOS 26
    ];
    for (const [macVersion, iosVersion] of pairs) {
        stubOSVersion(macVersion);
        const mac = resolveKeylogCallbackOffset("MacOS").offset;
        stubOSVersion(iosVersion);
        const ios = resolveKeylogCallbackOffset("iOS").offset;
        assert.equal(mac, ios, `${macVersion} (0x${mac.toString(16)}) != ${iosVersion} (0x${ios.toString(16)})`);
    }
});

test("no version source resolves to a bucket instead of throwing", () => {
    // The install-time validation is what protects a wrong guess; resolution
    // itself must always produce something and never throw.
    stubNoVersionSource();
    const resolved = resolveKeylogCallbackOffset("iOS");
    assert.equal(resolved.versionSource, "unknown");
    assert.equal(typeof resolved.offset, "number");
    assert.ok(resolved.offset > 0);
});

test("resolution reports provenance so the veto message can name it", () => {
    stubNoModule();
    stubOSVersion("Version 18.6 (Build 22G86)");
    const resolved = resolveKeylogCallbackOffset("iOS");
    assert.equal(resolved.provenance, "measured-from-apple-binary");
    assert.equal(resolved.major, 18);
    assert.ok(resolved.note.length > 0);
});
