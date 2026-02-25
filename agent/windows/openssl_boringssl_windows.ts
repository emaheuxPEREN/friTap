
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { socket_library } from "./windows_agent.js";
import { devlog, devlog_error } from "../util/log.js";
import { isSymbolAvailable } from "../shared/shared_functions.js";

export class OpenSSL_BoringSSL_Windows extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        let mapping:{ [key: string]: Array<string> } = {};
        mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new"]
        // Add key extraction symbols only if exported by this build
        if (isSymbolAvailable(moduleName, "SSL_CTX_set_keylog_callback")) {
            mapping[`*${moduleName}*`].push("SSL_CTX_set_keylog_callback")
        }
        if (isSymbolAvailable(moduleName, "SSL_get_SSL_CTX")) {
            mapping[`*${moduleName}*`].push("SSL_get_SSL_CTX")
        }
        if (isSymbolAvailable(moduleName, "SSL_CTX_new")) {
            mapping[`*${moduleName}*`].push("SSL_CTX_new")
        }
        mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        super(moduleName,socket_library, is_base_hook, mapping);
    }

    install_tls_keys_callback_hook(){
        // Guard: only proceed if SSL_CTX_set_keylog_callback was resolved
        const addrs = this.addresses[this.module_name];
        if (!addrs["SSL_CTX_set_keylog_callback"]) {
            devlog("SSL_CTX_set_keylog_callback not available for " + this.module_name + ", skipping key extraction");
            return;
        }

        this.SSL_CTX_set_keylog_callback = new NativeFunction(addrs["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;

        // Hook SSL_new to install keylog callback on each new SSL context
        try {
            Interceptor.attach(addrs["SSL_new"], {
                onEnter(args) {
                    try {
                        instance.SSL_CTX_set_keylog_callback(args[0], instance.keylog_callback);
                    } catch (e) {
                        devlog_error(`Error setting keylog callback in SSL_new: ${e}`);
                    }
                }
            });
        } catch (e) {
            devlog_error(`Failed to hook SSL_new for key extraction: ${e}`);
        }

        // Hook SSL_CTX_new if available — fallback for contexts created before SSL_new hook
        if (addrs["SSL_CTX_new"]) {
            try {
                Interceptor.attach(addrs["SSL_CTX_new"], {
                    onLeave(retval) {
                        try {
                            if (!retval.isNull()) {
                                instance.SSL_CTX_set_keylog_callback(retval, instance.keylog_callback);
                            }
                        } catch (e) {
                            devlog_error(`Error setting keylog callback in SSL_CTX_new: ${e}`);
                        }
                    }
                });
            } catch (e) {
                devlog_error(`Failed to hook SSL_CTX_new for key extraction: ${e}`);
            }
        }

        // Intercept app-set keylog callbacks
        try {
            Interceptor.attach(addrs["SSL_CTX_set_keylog_callback"], {
                onEnter(args) {
                    let callback_func = args[1];
                    Interceptor.attach(callback_func, {
                        onEnter(args) {
                            var message: { [key: string]: string | number | null } = {};
                            message["contentType"] = "keylog";
                            message["keylog"] = args[1].readCString();
                            send(message);
                        }
                    });
                }
            });
        } catch (e) {
            devlog_error(`Failed to hook SSL_CTX_set_keylog_callback interception: ${e}`);
        }
    }

    execute_hooks(){
        try { this.install_plaintext_read_hook(); }
        catch(e) { devlog_error(`Failed to install plaintext read hook: ${e}`); }

        try { this.install_plaintext_write_hook(); }
        catch(e) { devlog_error(`Failed to install plaintext write hook: ${e}`); }

        try { this.install_tls_keys_callback_hook(); }
        catch(e) { devlog_error(`Failed to install TLS keys callback hook: ${e}`); }

        try { this.install_extended_hooks(); }
        catch(e) { devlog_error(`Failed to install extended hooks: ${e}`); }
    }

}

export class OpenSSL_From_Python_Windows extends OpenSSL_BoringSSL {

    
    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){

        var library_method_mapping: { [key: string]: Array<string> } = {}

        // the MacOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_set_keylog_callback", "SSL_CTX_new", "SSL_new", "SSL_get_SSL_CTX"] 

        super(moduleName, socket_library, is_base_hook, library_method_mapping);
    }

    install_openssl_keys_callback_hook(){
        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;

        try {

            const ssl_new_ptr = this.addresses[this.module_name]["SSL_new"];
            const ssl_get_ctx_ptr = this.addresses[this.module_name]["SSL_get_SSL_CTX"];
            const set_keylog_cb_ptr = this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"];

            if (!ssl_new_ptr || !ssl_get_ctx_ptr || !set_keylog_cb_ptr) {
                devlog_error(`Required functions not found in ${this.module_name}`);
                return;
            }
            const SSL_get_SSL_CTX = new NativeFunction(ssl_get_ctx_ptr,'pointer', ['pointer']) as (ssl: NativePointer) => NativePointer;

            Interceptor.attach(ssl_new_ptr, {
                onEnter(args: InvocationArguments): void {
                    //devlog(`SSL_new called in ${instance.module_name}`);
                },
                onLeave(retval: InvocationReturnValue): void {
                    if (retval.isNull()) {
                        devlog_error("SSL_new returned NULL");
                        return;
                    }

                    const ssl_ptr = retval as NativePointer;
                    const ctx_ptr = SSL_get_SSL_CTX(ssl_ptr);

                    if (ctx_ptr.isNull()) {
                        devlog_error("SSL_get_SSL_CTX returned NULL");
                        return;
                    }

                    //devlog(`Installing keylog callback on ctx: ${ctx_ptr}`); // Uncomment for debugging

                    try {
                        devlog("Installing callback for OpenSSL_From_Python for module: " + instance.module_name);
                        instance.SSL_CTX_set_keylog_callback(ctx_ptr, instance.keylog_callback);
                    } catch (e) {
                        devlog_error(`Failed to set keylog callback: ${e}`);
                    }
                }
            });

        } catch (e) {
            devlog_error(`Error hooking ${instance.module_name}: ${e}`);
        }

        

        // In case a callback is set by the application, we attach to this callback instead
        // Only succeeds if SSL_CTX_new is available
        Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], {
            onEnter: function (args: any) {
                let callback_func = args[1];

                Interceptor.attach(callback_func, {
                    onEnter: function (args: any) {
                        var message: { [key: string]: string | number | null } = {};
                        message["contentType"] = "keylog";
                        message["keylog"] = args[1].readCString();
                        send(message);
                    }
                });
            }
        });
    }

    

    execute_hooks(){
        /*
        currently these function hooks aren't implemented
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        */

        this.install_openssl_keys_callback_hook();
    }

    

}


export function boring_execute(moduleName:string, is_base_hook: boolean){
    var boring_ssl = new OpenSSL_BoringSSL_Windows(moduleName,socket_library, is_base_hook);
    boring_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = boring_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}

export function ssl_python_execute(moduleName:string, is_base_hook: boolean){
    var openssl = new OpenSSL_From_Python_Windows(moduleName,socket_library, is_base_hook);
    openssl.execute_hooks();
    
    if (is_base_hook) {
        const init_addresses = openssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}