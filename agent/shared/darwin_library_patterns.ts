// agent/shared/darwin_library_patterns.ts
//
// Module-name and path predicates shared by the two Darwin platform agents
// (agent/platforms/macos.ts and agent/platforms/ios.ts).
//
// These live in their own module for a reason beyond deduplication: the
// correctness of the libssl routing rests on several registry entries consuming
// the SAME predicate object, so that one entry's filter is provably the exact
// complement of another's. Inlining any of them re-opens the class of bug they
// were introduced to close.

/**
 * A versioned OpenSSL/LibreSSL dylib name: `libssl.3.dylib`,
 * `libssl.1.1.dylib`, `libssl.48.dylib` (Apple's system LibreSSL). BoringSSL
 * never ships this name shape.
 *
 * Two details are load-bearing:
 *
 *  - `(^|\/)` rather than `^`. The registry is queried both with a bare module
 *    name (`Process.enumerateModules()`, via `getModuleNames()`) AND with the
 *    raw `dlopen(3)` argument (`shared_functions.ts`, the dynamic-loader hook),
 *    which is frequently a full path — `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib`
 *    — or an `@rpath/libssl.3.dylib` / `@loader_path/../lib/libssl.1.1.dylib`
 *    string. A `^`-only anchor matches none of those, which would leave the
 *    dynamic-load path routed to the generic BoringSSL entry: the wrong
 *    executor, and the very bug this predicate exists to fix.
 *
 *  - `(\.\d+)*` so `libssl.1.1.dylib` is covered. The predicate this replaced,
 *    `/^libssl\.\d+\.dylib$/`, could not match `1.1` (`\d+` does not span the
 *    dot). Homebrew `openssl@1.1` and Python 3.9-era framework builds therefore
 *    matched the generic entry too, and because `ssl_library_loader` invokes
 *    EVERY match, both the genuine-OpenSSL executor and the Apple BoringSSL one
 *    installed on the same module — the latter writing a struct offset into a
 *    real OpenSSL `SSL_CTX`.
 *
 * No `/g` or `/y` flag, so `.test()` is stateless and this one instance is
 * safely shared across every entry that references it.
 */
export const VERSIONED_LIBSSL_DYLIB = /(^|\/)libssl\.\d+(\.\d+)*\.dylib$/;

/**
 * Apple's system LibreSSL, at exactly `/usr/lib/libssl.<n>.dylib`.
 *
 * Anchored to the real filesystem root because the predicate this replaced was
 * the plain substring `"/usr/lib/"`, which also matched an app vendoring its own
 * sysroot (`.../MyApp.app/Contents/Frameworks/usr/lib/libssl.3.dylib`) and so
 * routed a bundled OpenSSL to the priority-150 LibreSSL hook.
 *
 * INVARIANT: this is simultaneously the LibreSSL entry's `pathFilter` and the
 * OpenSSL entry's `excludePathFilter`. Those two entries share an identical
 * `pattern`, so this predicate is the ONLY thing separating them. If the two
 * uses ever drift apart the result is either a module with no hook at all or a
 * module with two — silently, in both cases.
 */
export const SYSTEM_LIBRESSL_PATH = /^\/usr\/lib\/libssl\.\d+(\.\d+)*\.dylib$/;

/**
 * Any dylib whose name contains `libssl` — the superset of
 * {@link VERSIONED_LIBSSL_DYLIB}, used by the generic OpenSSL/BoringSSL entry
 * together with `excludePattern: VERSIONED_LIBSSL_DYLIB`. That pairing is what
 * makes the generic entry cover exactly "libssl-shaped but not versioned"
 * (`libssl.dylib`, `libssl_custom.dylib`, `mylibssl.3.dylib`).
 */
export const ANY_LIBSSL_DYLIB = /.*libssl.*\.dylib/;
