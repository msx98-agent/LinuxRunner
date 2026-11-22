import Foundation
import Security
import SwiftUI
import UniformTypeIdentifiers

enum BinarySigning {
    enum Result {
        case preservedSignature
        case signedCopy(URL)
    }

    enum Failure: LocalizedError {
        case invalidIdentity, missingIdentity, invalidBinary, invalidIdentifier, signingFailed, keychain(OSStatus)

        var errorDescription: String? {
            switch self {
            case .invalidIdentity: return "The .p12 and password must unlock a certificate with a matching private key and Apple team ID."
            case .missingIdentity: return "Import a signing identity in Settings first."
            case .invalidBinary: return "Only supported thin ARM64 iPhoneOS Mach-O binaries can be signed."
            case .invalidIdentifier: return "Enter a code-signing identifier containing only letters, numbers, dots, or hyphens."
            case .signingFailed: return "ZSign could not sign the copy. Check the signing certificate and its certificate chain."
            case .keychain(let status): return "Keychain error (\(status)): \(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error")"
            }
        }
    }

    private struct Identity: Codable {
        let archive: Data
        let password: String

        func withBytes<T>(_ body: (UnsafePointer<UInt8>?, Int, UnsafePointer<CChar>) -> T) -> T {
            print("BinarySigning.Identity.withBytes: opening in-memory identity")
            let result = archive.withUnsafeBytes { bytes in
                password.withCString { body(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, $0) }
            }
            print("BinarySigning.Identity.withBytes.end: callback completed")
            return result
        }
    }

    private static let maxIdentityBytes = 1024 * 1024
    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: (Bundle.main.bundleIdentifier ?? "dev.linuxrunner.app") + ".code-signing",
            kSecAttrAccount as String: "pkcs12-v1",
            kSecAttrSynchronizable as String: false
        ]
    }

    static func hasIdentity() throws -> Bool {
        print("BinarySigning.hasIdentity: checking Keychain")
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("BinarySigning.hasIdentity.error: \(status)")
            throw Failure.keychain(status)
        }
        print("BinarySigning.hasIdentity.end: status \(status)")
        return status == errSecSuccess
    }

    static func importIdentity(from url: URL, password: String) throws {
        print("BinarySigning.importIdentity: reading selected archive")
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true, let size = values.fileSize, (1...maxIdentityBytes).contains(size), !password.utf8.contains(0) else {
            print("BinarySigning.importIdentity.input: unsupported size or format")
            throw Failure.invalidIdentity
        }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let archive = try file.read(upToCount: maxIdentityBytes + 1) ?? Data()
        let identity = Identity(archive: archive, password: password)
        guard identity.withBytes({ LRZSignValidateIdentity($0, $1, $2) }) else {
            print("BinarySigning.importIdentity.validation: identity rejected")
            throw Failure.invalidIdentity
        }
        let attributes: [String: Any] = [
            kSecValueData as String: try PropertyListEncoder().encode(identity),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            print("BinarySigning.importIdentity.add: creating Keychain item")
            status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            print("BinarySigning.importIdentity.store: Keychain error \(status)")
            throw Failure.keychain(status)
        }
        print("BinarySigning.importIdentity.end: identity saved")
    }

    static func removeIdentity() throws {
        print("BinarySigning.removeIdentity: deleting Keychain item")
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("BinarySigning.removeIdentity.error: \(status)")
            throw Failure.keychain(status)
        }
        print("BinarySigning.removeIdentity.end: identity absent")
    }

    private static func load() throws -> Identity {
        print("BinarySigning.load: reading stored identity")
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &value)
        guard status != errSecItemNotFound else {
            print("BinarySigning.load.missing: no identity saved")
            throw Failure.missingIdentity
        }
        guard status == errSecSuccess, let data = value as? Data else {
            print("BinarySigning.load.error: \(status)")
            throw Failure.keychain(status == errSecSuccess ? errSecDecode : status)
        }
        let identity = try PropertyListDecoder().decode(Identity.self, from: data)
        print("BinarySigning.load.end: identity read")
        return identity
    }

    // Call off the main thread for trusted local build outputs; remove the returned copy's parent directory after use.
    static func signIfNeeded(_ source: URL, identifier: String) throws -> Result {
        print("BinarySigning.signIfNeeded: checking input without modifying it")
        guard source.isFileURL else {
            print("BinarySigning.signIfNeeded.input: expected a local file")
            throw Failure.invalidBinary
        }
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let initial = source.path.withCString { LRZSignInspect($0) }
        if initial == Int32(LRZSignPreserved) {
            print("BinarySigning.signIfNeeded.skip: existing signature left intact")
            return .preservedSignature
        }
        guard initial == Int32(LRZSignUnsigned) else {
            print("BinarySigning.signIfNeeded.unsupported: untouched input")
            throw Failure.invalidBinary
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")
        guard (1...255).contains(identifier.utf8.count), identifier.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            print("BinarySigning.signIfNeeded.identifier: invalid")
            throw Failure.invalidIdentifier
        }
        let identity = try load()
        let fm = FileManager.default
        let directory = fm.temporaryDirectory.appendingPathComponent("LinuxRunnerSigning-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var keep = false
        defer {
            if !keep {
                do { try fm.removeItem(at: directory) }
                catch { print("BinarySigning.signIfNeeded.cleanup: \(error)") }
            }
        }
        let copy = directory.appendingPathComponent("signed-macho")
        try fm.copyItem(at: source, to: copy)
        let permissions = try fm.attributesOfItem(atPath: copy.path)[.posixPermissions] as? NSNumber
        let mode = (permissions?.intValue ?? 0o600) & 0o777
        try fm.setAttributes([.posixPermissions: mode | 0o600], ofItemAtPath: copy.path)
        let status = identity.withBytes { bytes, count, password in
            copy.path.withCString { path in
                identifier.withCString { LRZSignTrustedBinaryCopy(path, $0, bytes, count, password) }
            }
        }
        switch status {
        case Int32(LRZSignPreserved):
            print("BinarySigning.signIfNeeded.stagedSkip: preserving signed input")
            return .preservedSignature
        case Int32(LRZSignBadIdentity):
            print("BinarySigning.signIfNeeded.identity: stored identity rejected")
            throw Failure.invalidIdentity
        case Int32(LRZSignCompleted):
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: copy.path)
            keep = true
            print("BinarySigning.signIfNeeded.end: signed copy ready")
            return .signedCopy(copy)
        default:
            print("BinarySigning.signIfNeeded.signer: failed with status \(status)")
            throw Failure.signingFailed
        }
    }
}

struct BinarySigningSettingsView: View {
    @State private var picker = false
    @State private var selection: URL?
    @State private var password = ""
    @State private var saved = false
    @State private var busy = false
    @State private var message = ""

    var body: some View {
        Form {
            Section {
                Text(saved ? "Signing identity saved" : "No signing identity saved")
                Button("Choose .p12 File…") { picker = true }.disabled(busy)
                if let selection {
                    Text(selection.lastPathComponent).foregroundColor(.secondary)
                    SecureField("Password (leave blank if none)", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button(saved ? "Replace Signing Identity" : "Save Signing Identity") { save(selection) }.disabled(busy)
                }
                if saved {
                    Button("Remove Saved Identity", role: .destructive, action: remove).disabled(busy)
                }
            } header: {
                Text("Signing Identity")
            } footer: {
                Text("The certificate, private key, and password stay in this device’s Keychain. Signing does not install or authorize an executable.")
            }
            if !message.isEmpty { Section { Text(message) } }
        }
        .navigationTitle("Code Signing")
        .onAppear(perform: refresh)
        .onDisappear { password = ""; selection = nil }
        .fileImporter(isPresented: $picker, allowedContentTypes: [.pkcs12]) { result in
            print("BinarySigningSettingsView.importer: processing selection")
            do {
                selection = try result.get()
                password = ""
                message = ""
                print("BinarySigningSettingsView.importer.end: file selected")
            } catch {
                report(error, at: "importer")
            }
        }
    }

    private func refresh() {
        print("BinarySigningSettingsView.refresh: checking saved identity")
        do {
            saved = try BinarySigning.hasIdentity()
            print("BinarySigningSettingsView.refresh.end: status loaded")
        } catch {
            report(error, at: "refresh")
        }
    }

    private func save(_ url: URL) {
        print("BinarySigningSettingsView.save: validating selected identity")
        let secret = password
        password = ""
        busy = true
        message = ""
        Task {
            defer { busy = false }
            do {
                try await Task.detached(priority: .userInitiated) { try BinarySigning.importIdentity(from: url, password: secret) }.value
                selection = nil
                saved = true
                message = "Signing identity saved."
                print("BinarySigningSettingsView.save.end: saved to Keychain")
            } catch {
                report(error, at: "save")
            }
        }
    }

    private func remove() {
        print("BinarySigningSettingsView.remove: clearing saved identity")
        do {
            try BinarySigning.removeIdentity()
            saved = false
            message = "Signing identity removed."
            print("BinarySigningSettingsView.remove.end: removed from Keychain")
        } catch {
            report(error, at: "remove")
        }
    }

    private func report(_ error: Error, at location: String) {
        let nsError = error as NSError
        print("BinarySigningSettingsView.\(location).error: \(nsError.domain) (\(nsError.code))")
        message = error.localizedDescription
    }
}
