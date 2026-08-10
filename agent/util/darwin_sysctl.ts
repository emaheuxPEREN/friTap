// agent/util/darwin_sysctl.ts
//
// Apple OS facts (product version, device family) read via sysctlbyname().
//
// WHY NOT JUST ASK FOUNDATION
// `[[NSProcessInfo processInfo] operatingSystemVersionString]` KILLS a spawned,
// not-yet-resumed process. Measured on macOS 26: `+processInfo` returns fine (an
// `_NSSwiftProcessInfo`), but sending `operatingSystemVersionString` to it takes
// the whole target down with "the connection is closed". In spawn mode neither
// UIKit nor AppKit is loaded yet, so friTap's iOS/macOS detection fell through to
// exactly that call and killed every spawned Apple target before a single hook was
// installed — the macOS reproduction of fkie-cad/friTap#65.
//
// sysctlbyname() is a plain libc syscall wrapper: no Objective-C runtime, no Swift
// runtime, no Foundation, no dyld work beyond libSystem (already resident). It is
// safe at the earliest point the agent can run, and it answers both questions we
// actually needed Foundation for:
//
//   kern.osproductversion -> "26.3.1" / "16.7.10"   (the OS version)
//   hw.product            -> "MacBookPro18,4" / "iPhone14,2"  (the device family)
//
// Values are memoized: they cannot change during the process lifetime, and the
// NativeFunction is created lazily so this module stays free of module-scope Frida
// calls (agent load must not do work — see the platform-module load path).

import { devlog } from "./log.js";

let _sysctlbyname: NativeFunction<number, [NativePointer, NativePointer, NativePointer, NativePointer, number]> | null = null;
let _sysctlUnavailable = false;

function getSysctl() {
    if (_sysctlbyname !== null || _sysctlUnavailable) return _sysctlbyname;
    try {
        const addr = Module.findGlobalExportByName("sysctlbyname");
        if (addr === null || addr.isNull()) {
            _sysctlUnavailable = true;
            return null;
        }
        _sysctlbyname = new NativeFunction(addr, "int",
            ["pointer", "pointer", "pointer", "pointer", "size_t"]);
        return _sysctlbyname;
    } catch (e) {
        _sysctlUnavailable = true;
        return null;
    }
}

/** Longest sysctl string we are willing to allocate for; all keys here are short. */
const MAX_SYSCTL_STRING = 1024;

/**
 * Read a string-valued sysctl, or null when unavailable. Never throws.
 * Two-call protocol: first query the size, then fetch into a right-sized buffer.
 */
export function sysctlString(name: string): string | null {
    const sysctl = getSysctl();
    if (sysctl === null) return null;
    try {
        const namePtr = Memory.allocUtf8String(name);
        const sizePtr = Memory.alloc(8);
        sizePtr.writeU64(0);
        if (sysctl(namePtr, NULL, sizePtr, NULL, 0) !== 0) return null;
        const size = sizePtr.readU64().valueOf() as number;
        if (size <= 0 || size > MAX_SYSCTL_STRING) return null;
        const buf = Memory.alloc(size);
        sizePtr.writeU64(size);
        if (sysctl(namePtr, buf, sizePtr, NULL, 0) !== 0) return null;
        return buf.readUtf8String();
    } catch (e) {
        devlog(`[sysctl] ${name} failed: ${e}`);
        return null;
    }
}

let _productVersion: string | null | undefined;

/** e.g. "26.3.1" (macOS) or "16.7.10" (iOS); null if unavailable. Memoized. */
export function darwinProductVersion(): string | null {
    if (_productVersion === undefined) _productVersion = sysctlString("kern.osproductversion");
    return _productVersion;
}

/** Major component of darwinProductVersion(), or -1. */
export function darwinMajorVersion(): number {
    const version = darwinProductVersion();
    if (version === null) return -1;
    const matched = version.match(/^(\d+)/);
    return matched === null ? -1 : parseInt(matched[1], 10);
}

let _deviceFamily: string | null | undefined;

/**
 * Device identifier, e.g. "MacBookPro18,4", "iPhone14,2", "iPad13,1".
 * Prefers hw.product; falls back to hw.machine, which carries the model on iOS
 * (on macOS hw.machine is just the CPU arch, which is why it is second).
 */
function deviceFamily(): string | null {
    if (_deviceFamily === undefined) {
        _deviceFamily = sysctlString("hw.product") ?? sysctlString("hw.machine");
    }
    return _deviceFamily;
}

const IOS_FAMILY_PREFIXES = ["iPhone", "iPad", "iPod", "Watch", "AppleTV", "AudioAccessory", "RealityDevice"];

/**
 * True on the iOS device family, false on macOS, null when it cannot be told
 * (caller should fall back to its own detection rather than guess).
 *
 * Deliberately reports null rather than a default: picking wrong here selects the
 * wrong hook set, and on Apple platforms it also selects the wrong SSL_CTX offset
 * table.
 */
export function isIOSFamilyBySysctl(): boolean | null {
    const family = deviceFamily();
    if (family === null) return null;
    for (const prefix of IOS_FAMILY_PREFIXES) {
        if (family.indexOf(prefix) === 0) return true;
    }
    // "Mac...", "MacBookPro...", "iMac...", "Macmini...", "MacPro..."
    if (family.indexOf("Mac") >= 0 || family.indexOf("iMac") === 0) return false;
    // Simulator runtimes report the host Mac's product, so an unrecognised value
    // is genuinely ambiguous — say so instead of guessing.
    return null;
}
