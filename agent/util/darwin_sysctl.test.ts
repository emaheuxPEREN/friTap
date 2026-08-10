// Unit tests for the Apple OS facts read via sysctlbyname() (darwin_sysctl.ts),
// and for the fact that it is the PRIMARY version source rather than a fallback.
//
// Run: npm run test:agent
//
// WHY THIS FILE IS SEPARATE FROM apple_keylog_offset.test.ts
// darwin_sysctl.ts memoizes everything at module scope (the values cannot change
// during a process lifetime) and exports no reset. node:test isolates per FILE, so
// "sysctl answers" and "sysctl is unavailable" need different files: the sibling
// file covers the NSProcessInfo fallback by leaving sysctlbyname unresolvable,
// this one opts in via stubSysctl() and covers the primary path.
//
// WHY THE ORDERING MATTERS AT ALL
// `-[NSProcessInfo operatingSystemVersionString]` KILLS a spawned, not-yet-resumed
// process — measured on macOS 26, and the macOS reproduction of fkie-cad/friTap#65
// (see the header of darwin_sysctl.ts). Hook installation runs inside exactly that
// pre-resume window, so "sysctl answered, therefore Foundation was never messaged"
// is a correctness invariant, not a performance detail. It is pinned below by a
// tripwire on the ObjC stub.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
// Side-effect import: defines Process/Module/Memory/etc. BEFORE the module under
// test loads. stubSysctl() is opt-in and is called from the test bodies, because
// getSysctl() resolves lazily on first use rather than at import.
import "../shared/frida-test-stubs.js";
import { stubSysctl } from "../shared/frida-test-stubs.js";
import { sysctlString, darwinProductVersion, darwinMajorVersion } from "./darwin_sysctl.js";
import { resolveKeylogCallbackOffset } from "../legacy/tls/shared/apple_keylog_offset.js";

const G = globalThis as any;

/** A plausible full answer set for a Mac, used wherever the values are incidental. */
const MAC_SYSCTL = {
    "kern.osproductversion": "26.3.1",
    "hw.product": "MacBookPro18,4",
    "hw.machine": "arm64",
};

/**
 * Arm the Foundation tripwire: NSProcessInfo answers `versionString` exactly as
 * apple_keylog_offset.test.ts's stubOSVersion() makes it answer, but every step of
 * the path — the ObjC.classes lookup, +processInfo, and the fatal
 * -operatingSystemVersionString message — records that it was reached.
 *
 * ObjC.available must be true, otherwise `foundationTouched === false` would hold
 * trivially and prove nothing about the ordering.
 */
function armFoundationTripwire(versionString: string): { touched: () => boolean } {
    let touched = false;
    const nsProcessInfo = {
        processInfo: () => {
            touched = true;
            return {
                operatingSystemVersionString: () => {
                    touched = true;
                    return { toString: () => versionString };
                },
            };
        },
    };
    G.ObjC.available = true;
    G.ObjC.classes = {};
    // A getter, so even *looking* NSProcessInfo up counts as reaching for Foundation.
    Object.defineProperty(G.ObjC.classes, "NSProcessInfo", {
        configurable: true,
        get: () => { touched = true; return nsProcessInfo; },
    });
    // No libboringssl and no CoreFoundation: keep resolution on the table path so
    // versionSource is the only thing under test here.
    G.Process.findModuleByName = () => null;
    return { touched: () => touched };
}

/**
 * Call `read` against a FRESH copy of darwin_sysctl.ts, whose module-scope memos
 * (_sysctlbyname / _productVersion / _deviceFamily) are therefore unset.
 *
 * Needed because the module deliberately exports no reset hook: production reads
 * each value at most once per process, and a per-process memo is the correct shape
 * for facts that cannot change. Requiring it through the CJS registry gives an
 * independent module instance sharing the same Frida global stubs, so each case
 * below exercises the real first-read path.
 */
const require = createRequire(import.meta.url);
function withFreshSysctl<T>(values: Record<string, string>, read: (mod: any) => T): T {
    stubSysctl(values);
    delete require.cache[require.resolve("./darwin_sysctl.ts")];
    return read(require("./darwin_sysctl.ts"));
}

test("darwinProductVersion() reports kern.osproductversion and majors parse from it", () => {
    // The primary path end to end: four Frida globals (findGlobalExportByName,
    // allocUtf8String, alloc, NativeFunction) plus the two-call size protocol.
    stubSysctl(MAC_SYSCTL);
    assert.equal(darwinProductVersion(), "26.3.1");
    assert.equal(darwinMajorVersion(), 26);
});

test("the keylog offset resolver reports sysctl as the version source", () => {
    // Guards the ordering in detectMajorVersion(): sysctl is consulted first, so a
    // target where sysctl works must never be attributed to NSProcessInfo.
    armFoundationTripwire("Version 15.1 (Build WRONG)");
    const resolved = resolveKeylogCallbackOffset("MacOS");
    assert.equal(resolved.versionSource, "sysctl");
    assert.equal(resolved.major, 26);
    assert.equal(resolved.versionDetail, "kern.osproductversion=26.3.1");
    assert.equal(resolved.offset, 0x310);   // macOS >= 15 bucket, matching iOS 18/26
});

test("Foundation is never messaged when sysctl answers", () => {
    // THE Phase-B invariant. Messaging NSProcessInfo takes a suspended spawn down
    // with "the connection is closed" (measured on macOS 26), and hook installation
    // happens before resume — so this must hold even though NSProcessInfo would
    // have answered correctly. Note the tripwire also fires on the bare
    // ObjC.classes.NSProcessInfo lookup, so this pins "did not even reach for it".
    const foundation = armFoundationTripwire("Version 26.3.1 (Build 25D771280a)");
    const resolved = resolveKeylogCallbackOffset("MacOS");
    assert.equal(resolved.versionSource, "sysctl");
    assert.equal(foundation.touched(), false, "detectMajorVersion() reached for Foundation despite sysctl answering");
});

test("sysctlString() returns null for a key the kernel does not know", () => {
    // sysctlbyname() fails the size query with -1/ENOENT; nothing may be read from
    // the uninitialised buffer.
    stubSysctl(MAC_SYSCTL);
    assert.equal(sysctlString("kern.no.such.key"), null);
});

test("sysctlString() refuses a value larger than the allocation bound", () => {
    // The MAX_SYSCTL_STRING guard: every key read here is short, so an implausible
    // reported size means something is wrong and must not drive an allocation.
    const verdict = withFreshSysctl(
        { "kern.osproductversion": "9".repeat(4096) },
        mod => mod.sysctlString("kern.osproductversion"),
    );
    assert.equal(verdict, null);
});

test("isIOSFamilyBySysctl(): hw.product naming an iPhone reports the iOS family", () => {
    // Selects both the hook set and, on Apple platforms, the SSL_CTX offset table.
    assert.equal(withFreshSysctl(
        { ...MAC_SYSCTL, "hw.product": "iPhone14,2" },
        mod => mod.isIOSFamilyBySysctl(),
    ), true);
});

test("isIOSFamilyBySysctl(): hw.product naming a Mac reports not-iOS", () => {
    assert.equal(withFreshSysctl(
        MAC_SYSCTL,
        mod => mod.isIOSFamilyBySysctl(),
    ), false);
});

test("isIOSFamilyBySysctl(): falls back to hw.machine, which carries the iOS model", () => {
    // On iOS hw.machine is the model ("iPad13,1"); on macOS it is only the CPU arch,
    // which is why hw.product is tried first.
    assert.equal(withFreshSysctl(
        { "kern.osproductversion": "18.6", "hw.machine": "iPad13,1" },
        mod => mod.isIOSFamilyBySysctl(),
    ), true);
});

test("isIOSFamilyBySysctl(): an unrecognised device reports null rather than guessing", () => {
    // Deliberate: picking wrong selects the wrong hook set AND the wrong offset
    // table, so the caller must be told to fall back to its own detection.
    assert.equal(withFreshSysctl(
        { ...MAC_SYSCTL, "hw.product": "SomeFutureThing9,1", "hw.machine": "SomeFutureThing9,1" },
        mod => mod.isIOSFamilyBySysctl(),
    ), null);
});

test("isIOSFamilyBySysctl(): null when sysctl cannot name the device at all", () => {
    assert.equal(withFreshSysctl(
        { "kern.osproductversion": "26.3.1" },
        mod => mod.isIOSFamilyBySysctl(),
    ), null);
});
