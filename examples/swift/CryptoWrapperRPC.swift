// SPDX-License-Identifier: GPL-3.0-only

import Foundation

enum CryptoWrapperRPCError: Error {
    case notStarted
    case serverClosed
    case malformedMessage
    case remote(code: Int, message: String, data: Any?)
}

/// A small synchronous JSON-RPC client suitable for wrapping in a Swift actor.
///
/// This example covers all non-secret methods. Secret-bearing calls additionally
/// require launching `cw` with an inherited descriptor 3 and writing CWS1 frames
/// to it; see `examples/go-rpc-client` and RPC.md for the complete launch flow.
final class CryptoWrapperRPC {
    typealias NotificationHandler = (_ method: String, _ params: [String: Any]) -> Void

    private let process = Process()
    private let requestPipe = Pipe()
    private let responsePipe = Pipe()
    private var responseBuffer = Data()
    private var nextID = 1
    private let callLock = NSLock()

    var onNotification: NotificationHandler?

    func start(cw: URL, openssl: URL? = nil) throws {
        process.executableURL = cw
        var arguments: [String] = []
        if let openssl {
            arguments += ["--openssl", openssl.path]
        }
        arguments += ["rpc", "--stdio"]
        process.arguments = arguments
        process.standardInput = requestPipe
        process.standardOutput = responsePipe
        process.standardError = FileHandle.standardError
        try process.run()
    }

    func call(method: String, params: [String: Any]? = nil) throws -> Any {
        callLock.lock()
        defer { callLock.unlock() }
        guard process.isRunning else {
            throw CryptoWrapperRPCError.notStarted
        }

        let id = nextID
        nextID += 1
        var request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        ]
        if let params {
            request["params"] = params
        }
        var encoded = try JSONSerialization.data(withJSONObject: request)
        encoded.append(0x0A)
        try requestPipe.fileHandleForWriting.write(contentsOf: encoded)

        while true {
            let messageData = try readLine()
            guard
                let message = try JSONSerialization.jsonObject(with: messageData) as? [String: Any]
            else {
                throw CryptoWrapperRPCError.malformedMessage
            }
            if message["id"] == nil {
                if
                    let notificationMethod = message["method"] as? String,
                    let notificationParams = message["params"] as? [String: Any]
                {
                    onNotification?(notificationMethod, notificationParams)
                }
                continue
            }
            guard (message["id"] as? Int) == id else {
                continue
            }
            if let error = message["error"] as? [String: Any] {
                throw CryptoWrapperRPCError.remote(
                    code: error["code"] as? Int ?? -32603,
                    message: error["message"] as? String ?? "unknown RPC error",
                    data: error["data"]
                )
            }
            guard let result = message["result"] else {
                throw CryptoWrapperRPCError.malformedMessage
            }
            return result
        }
    }

    func stop() {
        try? requestPipe.fileHandleForWriting.close()
        if process.isRunning {
            process.waitUntilExit()
        }
    }

    private func readLine() throws -> Data {
        while true {
            if let newline = responseBuffer.firstIndex(of: 0x0A) {
                let line = responseBuffer[..<newline]
                responseBuffer.removeSubrange(...newline)
                return Data(line)
            }
            guard
                let chunk = try responsePipe.fileHandleForReading.read(upToCount: 4096),
                !chunk.isEmpty
            else {
                throw CryptoWrapperRPCError.serverClosed
            }
            responseBuffer.append(chunk)
        }
    }
}

// Example:
//
// let client = CryptoWrapperRPC()
// try client.start(cw: URL(fileURLWithPath: "/usr/local/bin/cw"))
// defer { client.stop() }
// let handshake = try client.call(method: "system.handshake")
// print(handshake)
