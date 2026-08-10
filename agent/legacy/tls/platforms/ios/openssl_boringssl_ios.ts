
import {OpenSSL_BoringSSL } from "../../../../tls/libs/openssl_boringssl.js";
import { OpenSSL_From_Python_MacOS } from "../macos/openssl_boringssl_macos.js";
import { socket_library } from "../../../../platforms/ios.js";
import { log, devlog } from "../../../../util/log.js";
import { ObjC } from "../../../../shared/objclib.js";
import { patterns, isPatternReplaced, experimental } from "../../../../fritap_agent.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { installKeylogCallbackViaCtxWrite } from "../../shared/apple_keylog_offset.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";

export class OpenSSL_BoringSSL_iOS extends OpenSSL_BoringSSL {

    install_tls_keys_callback_hook(){
        //console.log(this.addresses) // currently only for debugging purposes will be removed in future releases
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            // Apple does not export SSL_CTX_set_keylog_callback, so the callback
            // is written straight into the SSL_CTX struct. The offset table and
            // the write-time validation live in apple_keylog_offset.ts — see
            // fkie-cad/friTap#65 for why an unchecked write here was fatal.
            const setInfoCallback = this.addresses[this.module_name]["SSL_CTX_set_info_callback"];
            if (setInfoCallback === undefined || setInfoCallback === null || setInfoCallback.isNull()) {
                devlog("[iOS] SSL_CTX_set_info_callback unresolved — cannot install the keylog callback");
                return;
            }
            installKeylogCallbackViaCtxWrite(setInfoCallback, this.keylog_callback, "iOS", this.module_name);
          }

    }


    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){

        var library_method_mapping: { [key: string]: Array<string> } = {}

        // the iOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        //library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"]
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_set_info_callback"]
        //library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"] // currently those functions gets only identified if we at an asterisk at the end

        super(moduleName,socket_library,is_base_hook,library_method_mapping);
    }

    async execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        await this.resolveWithPipelineAsync(["SSL_CTX_set_info_callback"]);

        this.install_tls_keys_callback_hook();
    }



}


// Opts libboringssl.dylib into exports -> enumerateSymbols() fallback resolution,
// for parity with every other platform executor. On Apple this is INERT by
// construction, and deliberately so — this is the struct-write keylog path of
// fkie-cad/friTap#65 and it must not change behaviour here:
//   - the library_method_mapping above requests exactly one symbol,
//     SSL_CTX_set_info_callback, and Apple EXPORTS it ('T _SSL_CTX_set_info_callback'
//     in nm on the iOS 17.0 / 17.5 / 18.6 / 26.2 simulator runtimes), so
//     readAddresses resolves it in the exports pass. The symbol-table fallback only
//     fills entries the exports pass MISSED and never overwrites an export hit.
//   - the base constructor's isSymbolAvailable() probes cannot flip either:
//     SSL_CTX_new is exported ('T') on all four runtimes, and SSL_read_ex /
//     SSL_write_ex do not exist in BoringSSL at all (absent from nm entirely), so
//     is_openssl stays false — and install_extended_hooks(), its only consumer, is
//     not called by this executor anyway.
//   - the keylog offset derivation in apple_keylog_offset.ts calls
//     Module.enumerateSymbols() directly for the LOCAL ('t')
//     _SSL_CTX_set_keylog_callback; it does not go through this opt-in.
// Adding SSL_CTX_set_keylog_callback to the mapping, i.e. calling Apple's setter
// instead of writing the struct field, is a separate deferred change.
export function boring_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_BoringSSL_iOS, moduleName, socket_library, is_base_hook);
}

// Genuine OpenSSL bundled inside an app (a versioned libssl.<n>.dylib). Reuses
// OpenSSL_From_Python_MacOS: despite the name, that class is platform-neutral —
// it maps only standard OpenSSL symbols (SSL_CTX_set_keylog_callback,
// SSL_CTX_new, SSL_new, SSL_get_SSL_CTX) and takes socket_library as a
// constructor argument, so binding iOS's constant here is the whole difference.
//
// Crucially this is NOT OpenSSL_BoringSSL_iOS: that executor writes the Apple
// BoringSSL keylog struct offset, which in a genuine OpenSSL SSL_CTX lands on an
// unrelated field. This one calls the library's own setter instead.
export function openssl_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_From_Python_MacOS, moduleName, socket_library, is_base_hook);
}
