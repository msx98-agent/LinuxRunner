import Foundation
import StikJIT

final class RequestHandler: NSObject, NSExtensionRequestHandling {
    private let queue = DispatchQueue(label: "dev.linuxrunner.stikjit.worker")

    func beginRequest(with context: NSExtensionContext) {
        NSLog("StikJITHelper.beginRequest: entering request")
        defer { NSLog("StikJITHelper.beginRequest: success, queued request") }
        queue.async {
            NSLog("StikJITHelper.worker: entering operation")
            defer { NSLog("StikJITHelper.worker: operation scope finished") }
            self.perform(context)
        }
    }

    private func perform(_ context: NSExtensionContext) {
        NSLog("StikJITHelper.perform: entering payload validation")
        defer { NSLog("StikJITHelper.perform: request scope finished") }
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".plist")
        do {
            NSLog("StikJITHelper.perform.do: entering operation")
            defer { NSLog("StikJITHelper.perform.do: operation finished") }
            guard let item = context.inputItems.first as? NSExtensionItem, let payload = item.userInfo, let pairing = payload["pairing"] as? Data, let pid = payload["pid"] as? NSNumber, let address = payload["address"] as? String else {
                NSLog("StikJITHelper.perform.payload: error, invalid request")
                throw NSError(domain: "StikJITHelper", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid helper request"])
            }
            try pairing.write(to: temporary, options: [.atomic, .completeFileProtectionUnlessOpen])
            defer { removePairingFile(temporary) }
            let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            let paths = DDIPaths.default(in: library.appendingPathComponent("StikJIT"))
            let configuration = StikJIT.Configuration(deviceAddress: address)
            let operation = payload["operation"] as? String ?? "enable"
            let result = try run(operation, pid.int32Value, temporary, paths, configuration, payload["forceScript"] as? Bool ?? false)
            let reply = NSExtensionItem()
            reply.userInfo = ["message": result]
            context.completeRequest(returningItems: [reply])
            NSLog("StikJITHelper.perform.complete: success, %@", result)
        } catch {
            NSLog("StikJITHelper.perform.catch: error, %@; stack=%@", String(reflecting: error), Thread.callStackSymbols)
            context.cancelRequest(withError: error)
        }
    }

    private func removePairingFile(_ file: URL) {
        NSLog("StikJITHelper.removePairingFile: entering temporary record cleanup")
        defer { NSLog("StikJITHelper.removePairingFile.end: cleanup scope finished") }
        do {
            NSLog("StikJITHelper.removePairingFile.do: entering removal")
            try FileManager.default.removeItem(at: file)
            NSLog("StikJITHelper.removePairingFile.do.end: success, temporary record removed")
        } catch {
            NSLog("StikJITHelper.removePairingFile.catch: error, %@; stack=%@", String(reflecting: error), Thread.callStackSymbols)
        }
    }

    private func run(_ operation: String, _ pid: Int32, _ pairing: URL, _ paths: DDIPaths, _ configuration: StikJIT.Configuration, _ forceScript: Bool) throws -> String {
        NSLog("StikJITHelper.run: entering %@ for PID %d at %@", operation, pid, configuration.deviceAddress)
        defer { NSLog("StikJITHelper.run: operation scope finished") }
        switch operation {
        case "reset":
            try StikJIT.resetCachedDDI(at: paths)
        case "prepare":
            let readiness = StikJIT.prepareDevice(pairingFile: pairing, paths: paths, configuration: configuration)
            guard case .ready = readiness else {
                NSLog("StikJITHelper.run.readiness: error, %@", String(describing: readiness))
                throw NSError(domain: "StikJITHelper", code: 2, userInfo: [NSLocalizedDescriptionKey: String(describing: readiness)])
            }
        default:
            try StikJIT.enableJIT(targetPID: pid, pairingFile: pairing, ddiPaths: paths, configuration: configuration, script: .universal, forceScript: forceScript, progress: Self.logProgress)
        }
        NSLog("StikJITHelper.run.result: success, %@ complete", operation)
        return "\(operation.capitalized) completed. TXM/SPTM: \(StikJIT.isTXMPresent.map { String($0) } ?? "Unknown")."
    }

    private static func logProgress(_ message: String) {
        NSLog("StikJITHelper.logProgress: entering progress callback")
        NSLog("StikJITHelper.logProgress.result: success, %@", message)
    }
}
