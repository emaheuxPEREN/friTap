
import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach } from "../../definitions/openssl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // iOS legacy uses struct-offset keylog via SSL_CTX_set_info_callback. Modern
    // mode runs THIS executor INSTEAD of the legacy struct-offset path (the
    // registry uses `use_modern ? boring_execute_modern : boring_execute`).
    //
    // Apple does NOT export SSL_CTX_set_keylog_callback — in libboringssl.dylib
    // it is a LOCAL symbol ('t _SSL_CTX_set_keylog_callback', body
    // `str x1, [x0, #0x310]; ret`; see agent/legacy/tls/shared/apple_keylog_offset.ts).
    // friTap's default resolution is exports-only, so the callback tier of the
    // chain can only ever resolve the setter through the symbol table. Hence the
    // deep-resolution opt-in below: it lets readAddresses fall back to
    // Module.enumerateSymbols(), which returns dyld-shared-cache locals.
    enableDeepSymbolResolution(moduleName);

    const def = createOpenSslDefinition({ skipReadWriteHooks: true });

    // Install the generic SSL_CTX_set_keylog_callback approach (calls the
    // target's OWN setter from the SSL_new hook — no struct-offset write here;
    // that raw write lives only in the legacy path). Without this the
    // definition's default keylog is { kind: "none" } and tier 1 of the chain
    // can never succeed, no matter what the binary contains.
    def.keylog = createBoringSSLKeylogApproach();

    // libraryType: "boringssl" routes through the three-tier hook chain in
    // agent/shared/boringssl_hook_chain.ts (callback / symbol / pattern).
    //
    // Tier 1 (callback) now depends on the symtab/deep lookup succeeding. That
    // lookup is verified against a live macOS dyld shared cache (4697 symbols,
    // including this one) and against standalone iOS Simulator runtime dylibs.
    // It has NEVER been run against a real iOS device: shipping iOS caches are
    // understood to possibly strip local symbols. If that is the case on-device,
    // tier 1 simply returns false and the chain falls through to tier 2
    // (bssl::ssl_log_secret symbol hook) exactly as it did before — where every
    // Apple --modern key came from until now, so no regression either way.
    // Should all three tiers ever be stripped, use_modern=false still gets the
    // legacy struct-offset path.
    def.libraryType = "boringssl";
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

// Genuine OpenSSL bundled inside an app (a versioned libssl.<n>.dylib in the
// bundle, or iOS's own /usr/lib LibreSSL falling back to this path). It must NOT
// be tagged libraryType: "boringssl" the way boring_execute_modern above is —
// that would send the hook chain hunting a bssl::ssl_log_secret symbol which
// cannot exist in OpenSSL, and then into a pointless Memory.scan. It also keeps
// the read/write hooks that boring_execute_modern deliberately skips.
//
// includeExSymbols is load-bearing: it is what puts SSL_CTX_new into the symbol
// list. The generic SSL_CTX_set_keylog_callback approach (misleadingly named
// createBoringSSLKeylogApproach) does no struct-offset write — it installs by
// calling the target's OWN setter from the SSL_new / SSL_CTX_new hooks. Deep
// symbol resolution is enabled for the same reason as above: that setter may be
// a local rather than an exported symbol.
export function openssl_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    const def = createOpenSslDefinition({ includeExSymbols: true });
    def.keylog = createBoringSSLKeylogApproach();
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
