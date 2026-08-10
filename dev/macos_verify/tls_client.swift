// TLS client for the macOS verification rig.
//
// Why Swift/URLSession rather than `curl` or a Python client: URLSession routes
// through CFNetwork, which on macOS/iOS uses Apple's own fork of BoringSSL in
// /usr/lib/libboringssl.dylib. That is exactly the library friTap's Apple
// keylog path hooks, and the one whose SSL_CTX layout the keylog-callback
// offset is derived from. A client using OpenSSL from Homebrew would exercise
// a completely different code path and prove nothing about the Apple platforms.
//
// A *fresh ephemeral* URLSession per round is deliberate: it forces a new
// SSL_CTX for every request, so the SSL_CTX-level callback installation is
// re-exercised continuously instead of once at startup. That is what makes a
// wrong offset show up as a dead target within seconds.
//
// Build:  swiftc -O tls_client.swift -o tls_client
// Usage:  ./tls_client [rounds] [url]

import Foundation

/// Accepts the rig's self-signed certificate. Scoped to this throwaway binary —
/// never copy this into anything that talks to a real server.
final class TrustEverything: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

let arguments = CommandLine.arguments
let rounds = arguments.count > 1 ? (Int(arguments[1]) ?? 10_000) : 10_000
let urlString = arguments.count > 2 ? arguments[2] : "https://localhost:8443/"

let semaphore = DispatchSemaphore(value: 0)
let delegate = TrustEverything()

func log(_ message: String) {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
}

for round in 1...rounds {
    let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
    var request = URLRequest(url: URL(string: urlString)!)
    request.timeoutInterval = 8
    session.dataTask(with: request) { data, response, error in
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        log("round \(round): status=\(status) bytes=\(data?.count ?? 0) "
            + "err=\(error?.localizedDescription ?? "-")")
        semaphore.signal()
    }.resume()
    _ = semaphore.wait(timeout: .now() + 12)
    session.invalidateAndCancel()
    Thread.sleep(forTimeInterval: 2.0)
}
