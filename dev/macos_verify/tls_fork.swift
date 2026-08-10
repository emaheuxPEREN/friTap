// tls_fork.swift — two-process TLS target for exercising friTap's multi-script path.
//
// WHY THIS EXISTS
// ---------------
// friTap's child-gating code path loads a *second* Frida script into a *second*
// process inside one friTap session. A regression made that second
// `script.load()` block forever waiting for the agent's startup handshake reply.
// Reproducing it used to require a real Android device. This program reproduces
// it locally: it performs TLS itself, then `posix_spawn`s a copy of itself that
// also performs TLS. `posix_spawn` is exactly what Frida's child gating
// intercepts, so one friTap session ends up instrumenting two processes.
//
// ROLES
//   ./tls_fork              -> parent: TLS rounds + spawn one child (role "child")
//   ./tls_fork --child      -> child:  TLS rounds only, never spawns
//
// Every TLS round builds a *fresh ephemeral* URLSession so a new SSL_CTX is
// created each time; that keeps friTap's BoringSSL hooks firing repeatedly
// instead of only once at startup. TLS goes through CFNetwork, i.e. through
// /usr/lib/libboringssl.dylib, which is the library friTap hooks on macOS.
//
// The server is expected at https://localhost:8443/ (see tls_server.py in the same
// directory). The self-signed certificate is trusted unconditionally by the
// URLSessionDelegate below — this binary is a test fixture, never ship it.
//
// Build:  swiftc -O tls_fork.swift -o tls_fork
// (Foundation/URLSession only; no third-party dependencies.)

import Foundation

// MARK: - Configuration

private let endpoint = URL(string: "https://localhost:8443/")!
private let roundDelaySeconds: TimeInterval = 1.5
private let requestTimeoutSeconds: TimeInterval = 8
private let totalRounds = 10_000            // effectively "until killed"
private let spawnChildAfterRound = 1        // parent spawns its child this early

// MARK: - Role

private enum Role: String {
    case parent = "parent"
    case child = "child"

    /// The child is selected by an explicit `--child` flag so that the parent's
    /// own argv (what friTap spawns) stays argument-free and simple to type.
    static func fromCommandLine() -> Role {
        CommandLine.arguments.contains("--child") ? .child : .parent
    }
}

private let role = Role.fromCommandLine()

/// Single logging entry point so parent and child lines are trivially greppable
/// and always carry the pid that produced them.
private func log(_ message: String) {
    let line = "[\(role.rawValue) pid=\(getpid())] \(message)\n"
    FileHandle.standardError.write(line.data(using: .utf8)!)
}

// MARK: - TLS

/// Accepts the fixture's self-signed certificate.
private final class TrustEverything: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

private let trustDelegate = TrustEverything()

/// Performs one blocking HTTPS round trip on a brand-new ephemeral session.
private func performTLSRound(_ round: Int) {
    let session = URLSession(configuration: .ephemeral,
                             delegate: trustDelegate,
                             delegateQueue: nil)
    defer { session.invalidateAndCancel() }

    var request = URLRequest(url: endpoint)
    request.timeoutInterval = requestTimeoutSeconds

    let done = DispatchSemaphore(value: 0)
    session.dataTask(with: request) { data, response, error in
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        log("round \(round): status=\(status) bytes=\(data?.count ?? 0) "
            + "err=\(error?.localizedDescription ?? "-")")
        done.signal()
    }.resume()

    _ = done.wait(timeout: .now() + requestTimeoutSeconds + 4)
}

// MARK: - Child spawning

/// Spawns this same executable with `--child` via `posix_spawn`.
///
/// `posix_spawn` (rather than Foundation's `Process`) is used deliberately and
/// directly: it is the syscall path Frida's child gating hooks, and calling it
/// here keeps the interception point obvious to anyone reading this fixture.
private func spawnChild() {
    // /proc does not exist on Darwin, so resolve our own image from argv[0] the
    // way the shell handed it to us; friTap always spawns us by absolute path.
    let executable = CommandLine.arguments[0]

    var pid: pid_t = 0
    let argv: [String] = [executable, "--child"]
    var cArgv: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) }
    cArgv.append(nil)
    defer { cArgv.forEach { if let p = $0 { free(p) } } }

    // Inherit the parent's environment and stderr so the child's rounds land in
    // the same captured output stream as the parent's.
    let status = posix_spawn(&pid, executable, nil, nil, &cArgv, environ)
    if status == 0 {
        log("posix_spawn -> child pid=\(pid)")
    } else {
        log("posix_spawn FAILED status=\(status) (\(String(cString: strerror(status))))")
    }
}

// MARK: - Main

log("starting; endpoint=\(endpoint.absoluteString)")

for round in 1...totalRounds {
    performTLSRound(round)

    if role == .parent && round == spawnChildAfterRound {
        spawnChild()
    }

    Thread.sleep(forTimeInterval: roundDelaySeconds)

    // Orphan guard: test runs end by SIGKILLing the parent, which would
    // otherwise leave the child running forever. Once reparented to launchd
    // (ppid 1) the child stops on its own, so a run never leaks strays.
    if role == .child && getppid() == 1 {
        log("parent gone — exiting")
        break
    }
}
