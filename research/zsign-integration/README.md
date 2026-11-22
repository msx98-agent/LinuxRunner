# ZSign integration

Settings → Signing → Code Signing imports, replaces, or removes a `.p12` plus password. Both are kept in one non-synchronizing, device-only Keychain item and only read when the device is unlocked. No credentials are used by the build or written to a temporary file.

`BinarySigning.signIfNeeded(_:identifier:)` is a backend entry point for trusted local build output. Call it off the main thread. It returns either `.preservedSignature` (use the source unchanged) or `.signedCopy(URL)` (caller must remove the copy's parent directory when done). There is no launcher or user-facing signing action.

Supported signing inputs are thin, unencrypted ARM64 iPhoneOS Mach-O executables, dylibs and bundles (single files, not IPA or `.app` directory signing). If a supported Mach-O layout already has an `LC_CODE_SIGNATURE` pointing inside the file, the signer preserves it without opening the Keychain. This deliberately also preserves ad-hoc or untrusted signatures; it does not claim that a signature is valid or that iOS will allow the binary to execute. Unsupported files are never changed. Signing uses the team ID from the certificate subject and does not add provisioning or custom entitlements.

`scripts/build-zsign.sh` pins and checksum-verifies ZSign and OpenSSL. It embeds a small static subset of ZSign and uses the OpenSSL default and legacy providers in-process; there is no CLI subprocess and no password on a command line. `python3 research/zsign-integration/smoke.py` builds and exercises the native backend on Linux with a throwaway CA, a test PKCS#12 and synthetic Mach-O fixtures. This does not test iOS Keychain, provisioning or runtime authorization.
