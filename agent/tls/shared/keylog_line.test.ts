// Unit tests for crash-safe keylog line reading/validation (keylog_line.ts).
//
// Run: npm run test:agent
//
// Why this exists: on Apple platforms friTap installs its BoringSSL keylog
// callback by writing the callback pointer into the SSL_CTX struct at a
// version-keyed offset. When that offset is stale the pointer can land on a
// neighbouring field whose callback has a DIFFERENT signature — info_callback is
// (SSL*, int, int) — so BoringSSL invokes our 2-pointer callback with a small
// integer where a string address is expected. Dereferencing it SIGSEGVs the whole
// target process, which is what made friTap unusable on iOS (fkie-cad/friTap#65).
// These tests lock both halves of the mitigation: an unreadable/bogus pointer
// yields null rather than a fault, and a payload that is not an NSS keylog line
// is rejected instead of being shipped to the host as key material.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Memory/etc. BEFORE keylog_line.js loads.
import "../../shared/frida-test-stubs.js";
import { isNssKeylogLine, readKeylogLine, NSS_KEYLOG_LABELS } from "./keylog_line.js";

const G = globalThis as any;

/**
 * Build a fake NativePointer whose readability is controlled by `readableUpTo`
 * bytes and which yields `content` from readCString(). Mirrors what
 * Process.findRangeByAddress-based validation sees: a pointer inside a mapping
 * that ends after `readableUpTo` bytes.
 */
function fakePointer(address: number, content: string | null, readableUpTo: number) {
    // Emulates a NUL-terminated C string followed by unrelated heap bytes, which
    // is what a real keylog buffer looks like. readByteArray() therefore returns
    // the terminator AND trailing junk — exactly the case that must not leak into
    // the returned string.
    const encode = (len: number): ArrayBuffer => {
        const out = new Uint8Array(len);
        const body = content ?? "";
        for (let i = 0; i < len; i++) {
            if (i < body.length) out[i] = body.charCodeAt(i);
            else if (i === body.length) out[i] = 0;          // terminator
            else out[i] = 0xAA;                              // trailing heap junk
        }
        return out.buffer;
    };
    return {
        _address: address,
        _readableUpTo: readableUpTo,
        isNull: () => address === 0,
        and: function () { return this; },
        add: function (n: number) { return fakePointer(address + n, content, readableUpTo - n); },
        compare: function (other: any) {
            return address === other._address ? 0 : (address < other._address ? -1 : 1);
        },
        readByteArray: (len: number) => {
            if (readableUpTo < 1) throw new Error("SIGSEGV (test)");
            return content === null ? null : encode(len);
        },
        readUtf8String: (len: number) => {
            if (readableUpTo < 1) throw new Error("SIGSEGV (test)");
            return content === null ? null : (content as string).substring(0, len);
        },
    };
}

/** Point Process.findRangeByAddress at a mapping that ends `readableUpTo` bytes in. */
function stubRangeFor(p: any, protection = "rw-"): void {
    G.Process.findRangeByAddress = (addr: any) => {
        if (p._readableUpTo <= 0) return null;
        return {
            base: fakePointer(addr._address, null, 0),
            size: p._readableUpTo,
            protection,
        };
    };
}

test("every declared label is accepted with a space separator", () => {
    for (const label of NSS_KEYLOG_LABELS) {
        const line = `${label} ${"a".repeat(64)} ${"b".repeat(96)}`;
        assert.equal(isNssKeylogLine(line), true, `rejected a valid ${label} line`);
    }
});

test("QUIC_-prefixed labels are accepted (BoringSSL reuses them for QUIC)", () => {
    assert.equal(isNssKeylogLine(`QUIC_CLIENT_TRAFFIC_SECRET_0 ${"a".repeat(64)} ${"b".repeat(64)}`), true);
});

test("a colon separator is tolerated (older friTap emitters use it)", () => {
    assert.equal(isNssKeylogLine(`CLIENT_RANDOM: ${"a".repeat(64)} ${"b".repeat(96)}`), true);
});

test("the wrong-signature case is rejected: garbage payloads are not keylog lines", () => {
    // What an info_callback invocation actually produces once decoded from a
    // small integer masquerading as a char*: short, label-less noise.
    for (const bogus of ["", "", "16", "not a keylog line at all", "SSL_CB_HANDSHAKE_START"]) {
        assert.equal(isNssKeylogLine(bogus), false, `accepted bogus payload ${JSON.stringify(bogus)}`);
    }
});

test("a label prefix is not enough — the separator must follow the full label", () => {
    // Guards against a longer label being truncated into a shorter one and
    // against arbitrary text that merely starts like a label.
    assert.equal(isNssKeylogLine("CLIENT_RANDOMISH aabbccdd eeff0011 2233"), false);
    assert.equal(isNssKeylogLine("EXPORTER_SECRETS aabbccdd eeff0011 2233"), false);
});

test("readKeylogLine returns null for a NULL pointer instead of dereferencing", () => {
    assert.equal(readKeylogLine(fakePointer(0, "CLIENT_RANDOM aa bb", 256) as any), null);
});

test("readKeylogLine returns null for an unmapped pointer (the SIGSEGV case)", () => {
    // ptr(0x10) — what `linePtr` holds when the callback was wired to
    // info_callback and receives an SSL_CB_* type code instead of an address.
    const p = fakePointer(0x10, "unreachable", 0);
    stubRangeFor(p);
    assert.equal(readKeylogLine(p as any), null);
});

test("readKeylogLine stops at the NUL and does not append trailing heap bytes", () => {
    // Regression test: a bounded readCString(size) reads the FULL window rather
    // than stopping at the terminator, which appended garbage after the secret in
    // the emitted keylog line (caught end-to-end on macOS).
    const line = "CLIENT_TRAFFIC_SECRET_0 " + "a".repeat(64) + " " + "b".repeat(96);
    const p = fakePointer(0x40000000, line, 512);
    stubRangeFor(p);
    assert.equal(readKeylogLine(p as any), line);
});

test("readKeylogLine reads a line that sits in a short but valid mapping", () => {
    // Only 32 bytes readable: the 256/128/64 probes must fail and the 16-byte
    // window must succeed, rather than the read running off the mapping.
    const line = "CLIENT_RANDOM aabbccdd eeff0011";
    const p = fakePointer(0x40000000, line, 32);
    stubRangeFor(p);
    const read = readKeylogLine(p as any);
    assert.notEqual(read, null);
    assert.equal(isNssKeylogLine(read as string), true);
});

test("readKeylogLine returns null when the mapping is not readable", () => {
    const p = fakePointer(0x40000000, "CLIENT_RANDOM aa bb", 256);
    stubRangeFor(p, "--x");   // execute-only: isReadable must refuse
    assert.equal(readKeylogLine(p as any), null);
});
