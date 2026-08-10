// agent/tls/shared/keylog_line.ts
//
// Crash-safe reading and shape-validation of an NSS keylog line handed to us by
// a native TLS keylog callback.
//
// Why this is not just `linePtr.readCString()`:
//
// On Apple platforms friTap installs its keylog callback by WRITING the callback
// pointer into the SSL_CTX struct at a version-keyed offset, because Apple does
// not export SSL_CTX_set_keylog_callback (see
// agent/legacy/tls/shared/apple_keylog_offset.ts). If that offset is stale the
// pointer can land on a neighbouring callback field with a completely different
// signature — info_callback is `void(*)(const SSL*, int type, int val)` — and
// BoringSSL will then invoke our 2-pointer callback with a small integer where we
// expect a string address. `readCString()` on ptr(0x10) SIGSEGVs and takes the
// whole target process down; Frida's JS try/catch cannot catch a native fault.
// So: range-check first, then sanity-check the shape (fkie-cad/friTap#65).

import { isReadable, resetReadableCache } from "../../util/safe_memory.js";

/** Longest plausible NSS keylog line: label + 64 hex client random + 96 hex secret + separators. */
const MAX_KEYLOG_LINE = 256;

/** Shortest plausible line: the shortest label ("EXPORTER_SECRET") plus a separator. */
const MIN_KEYLOG_LINE = 16;

/**
 * NSS/SSLKEYLOGFILE labels emitted by BoringSSL and OpenSSL keylog callbacks.
 * QUIC_-prefixed duplicates are matched by the prefix check below.
 */
export const NSS_KEYLOG_LABELS: ReadonlyArray<string> = [
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
];

/**
 * True when `line` starts with a known NSS keylog label followed by a separator.
 * Deliberately prefix-based rather than a full parse: the goal is to reject
 * garbage produced by a mis-wired callback, not to validate key material. A
 * "QUIC_" prefix is tolerated because BoringSSL's QUIC paths reuse the labels.
 */
export function isNssKeylogLine(line: string): boolean {
    if (line.length < MIN_KEYLOG_LINE) return false;
    const body = line.startsWith("QUIC_") ? line.substring(5) : line;
    for (const label of NSS_KEYLOG_LABELS) {
        if (!body.startsWith(label)) continue;
        // A real line separates the label from the hex with a space (or a colon in
        // a couple of older friTap emitters). Guard against a longer label being
        // truncated into a shorter one (e.g. EXPORTER_SECRET vs EARLY_EXPORTER_SECRET).
        const separator = body.charAt(label.length);
        if (separator === " " || separator === ":") return true;
    }
    return false;
}

/**
 * Read a NUL-terminated keylog line without risking a native fault.
 *
 * Probes progressively smaller windows for a mapped, readable range and reads
 * within the largest one that validates, so the read can never run off the end
 * of a mapping. Returns null when nothing readable is there — which is exactly
 * the "the offset was wrong and this is not a pointer" case.
 */
export function readKeylogLine(linePtr: NativePointer): string | null {
    if (linePtr === null || linePtr.isNull()) return null;
    resetReadableCache();  // mapped ranges can change between invocations
    for (const window of [MAX_KEYLOG_LINE, 128, 64, 32, MIN_KEYLOG_LINE]) {
        if (!isReadable(linePtr, window)) continue;
        try {
            // Find the NUL ourselves rather than trusting readCString(size) to stop
            // at it: with an explicit size it reads the full window, so a keylog
            // line shorter than the window comes back with trailing heap bytes
            // appended (observed as garbage after the secret). One bounded native
            // read plus a JS scan keeps the read in-bounds AND the string exact.
            const raw = linePtr.readByteArray(window);
            if (raw === null) return null;
            const bytes = new Uint8Array(raw);
            let end = bytes.indexOf(0);
            if (end === -1) end = bytes.length;   // no terminator inside the window
            if (end === 0) return null;
            return linePtr.readUtf8String(end);
        } catch (e) {
            return null;
        }
    }
    return null;
}
