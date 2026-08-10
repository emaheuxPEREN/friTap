import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach, createSslReadWriteExHooks } from "../../definitions/openssl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // Statically-linked OpenSSL/BoringSSL hosts may keep SSL_* in .symtab rather
    // than .dynsym; opt the module into the exports-first symbol-table fallback.
    enableDeepSymbolResolution(moduleName);

    const def = createOpenSslDefinition({ includeExSymbols: true });

    // Use shared BoringSSL keylog callback installation
    def.keylog = createBoringSSLKeylogApproach();

    // Add SSL_read_ex / SSL_write_ex as extra hooks
    def.extraHooks = createSslReadWriteExHooks();

    // Tag as BoringSSL so the loader auto-installs the bssl::ssl_log_secret
    // symbol fallback when SSL_CTX_set_keylog_callback can't be resolved.
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
