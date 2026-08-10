// agent/legacy/tls/platforms/ios/libressl_ios.ts
//
// Legacy (class-based) LibreSSL executor for iOS.
//
// Reuses LibreSSL_MacOS rather than subclassing or copying it: that class is
// ~250 lines of keylog-callback and KDF-hook logic (tls1_PRF,
// tls13_hkdf_expand_label) which is a property of LibreSSL itself, not of macOS,
// and Apple ships the same library on both OSes. The only platform-specific
// input is socket_library, which the class already takes as a constructor
// argument — so binding iOS's own constant here is the whole difference.

import { LibreSSL_MacOS } from "../macos/libressl_macos.js";
import { socket_library } from "../../../../platforms/ios.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export function libressl_execute(moduleName: string, is_base_hook: boolean) {
    executeSSLLibrary(LibreSSL_MacOS, moduleName, socket_library, is_base_hook);
}
