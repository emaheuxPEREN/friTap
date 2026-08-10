
import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach } from "../../definitions/openssl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // Statically-linked hosts may keep SSL_* out of the export directory; opt the
    // module into the exports-first symbol-table fallback. On a PE without a PDB
    // enumerateSymbols() simply finds nothing and resolution falls through.
    enableDeepSymbolResolution(moduleName);

    // Windows: SSL_CTX_set_keylog_callback is not exported by default on most
    // BoringSSL-flavoured DLLs, so the v2 definition leaves keylog at
    // { kind: "none" } for read/write-only coverage. Tagging libraryType:
    // "boringssl" lets the loader auto-install the bssl::ssl_log_secret
    // symbol hook — for genuine OpenSSL DLLs this is a harmless symbol-table
    // walk that finds nothing and falls through; for BoringSSL forks it is
    // the only working keylog path on Windows.
    const def = createOpenSslDefinition();
    def.libraryType = "boringssl";
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

export function ssl_python_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);

    const def = createOpenSslDefinition({ includeExSymbols: true });

    // Python links genuine OpenSSL: install the keylog callback via the target's
    // own SSL_CTX_set_keylog_callback (the definition default captures no keys).
    // Deliberately NOT tagged libraryType "boringssl" — bssl::ssl_log_secret
    // cannot exist here.
    def.keylog = createBoringSSLKeylogApproach();

    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
