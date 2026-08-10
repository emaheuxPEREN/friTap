// agent/tls/platforms/ios/libressl_ios.ts
//
// Modern (definition-based) LibreSSL executor for iOS.
//
// iOS ships LibreSSL in the dyld shared cache at /usr/lib/libssl.<n>.dylib, the
// same as macOS, and the LibreSSL definition is platform-neutral — so this is a
// thin re-bind of the shared definition onto iOS's own socket_library rather
// than a second copy of it. The file exists (instead of ios.ts importing the
// macOS executor) to keep each platform agent importing only from its own
// platform directory, matching cronet_ios.ts / cronet_macos.ts.

import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLibreSslDefinition } from "../../definitions/libressl.js";

export function libressl_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createLibreSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
