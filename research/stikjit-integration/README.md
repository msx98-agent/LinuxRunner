# StikJIT integration reference

Upstream: https://github.com/StikDebug/StikJIT, pinned at `a9ccad90c7a8cb547f77ff338890e6633a65ac43` in `deps/StikJIT`.

Reproduce the API review by reading `deps/StikJIT/INTEGRATION.md`, `Sources/StikJIT.swift`, `Sources/JITSession.swift`, and `Scripts/universal.js`. `scripts/build-stikjit.sh` builds the pinned source with the local Xcode rather than depending on release Swift compiler compatibility. `scripts/check-stikjit-ipa.py` checks the packaged helper, framework, universal script, deployment target, and network declarations.

The upstream API is blocking and cannot debug its own process. LinuxRunner launches its `NSExtensionRequestHandling` action helper through Foundation's private `NSExtension` host SPI. Pairing data travels in an extension item and is written to a temporary helper-local file. Operations run on one serial queue. The host checks its own `get-task-allow` entitlement, participates in the existing universal breakpoint protocol while the helper is attached, and retains verified runtime status as the activation authority. An IPA build does not establish physical-device JIT compatibility.

The default tunnel endpoint for this integration is `10.254.0.1`, editable in Execution Engine settings; StikJIT resolves the remote pairing port. The helper retains its DDI cache in its Library directory. Pairing import uses security-scoped file access, validates required plist fields, replaces the private stored file atomically, and excludes it from backup.

No binary reverse engineering is needed: this integration uses the upstream source API and documented universal script protocol.
