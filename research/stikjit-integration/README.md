# StikJIT integration reference

Upstream: https://github.com/StikDebug/StikJIT, pinned at `a9ccad90c7a8cb547f77ff338890e6633a65ac43` in `deps/StikJIT`.

Reproduce the API review by reading `deps/StikJIT/INTEGRATION.md`, `Sources/StikJIT.swift`, `Sources/JITSession.swift`, and `Scripts/universal.js`. `scripts/build-stikjit.sh` builds the pinned source with the local Xcode rather than depending on release Swift compiler compatibility. `scripts/check-stikjit-ipa.py` checks the packaged helper, framework, universal script, deployment target, and network declarations.

The upstream API is blocking and cannot debug its own process. LinuxRunner launches its `NSExtensionRequestHandling` action helper through Foundation's private `NSExtension` host SPI. Pairing data travels in an extension item and is written to a temporary helper-local file. Operations run on one serial queue. The host checks its own `get-task-allow` entitlement, participates in the existing universal breakpoint protocol while the helper is attached, and retains verified runtime status as the activation authority. An IPA build does not establish physical-device JIT compatibility.

The default tunnel endpoint for this integration is `10.254.0.1`, editable in Execution Engine settings; StikJIT resolves the remote pairing port. The helper retains its DDI cache in its Library directory. Pairing import uses security-scoped file access, validates required plist fields, replaces the private stored file atomically, and excludes it from backup.

No binary reverse engineering is needed: this integration uses the upstream source API and documented universal script protocol.

## Pairing file format

Both `Sources/JITSession.swift` and `Sources/DDISession.swift` call `rp_pairing_file_read` (verify with `rg -n rp_pairing_file_read deps/StikJIT/Sources`). The [idevice Remote Pairing parser](https://docs.rs/idevice/0.1.68/src/idevice/remote_pairing/rp_pairing_file.rs.html) expects `public_key` and `private_key` as 32-byte plist data fields, a string `identifier`, and optional `alt_irk` data. The legacy Lockdown fields `HostID`, `SystemBUID`, and `HostPrivateKey` describe a different format and must not be required by LinuxRunner's import or Documents preflight.

## Clean build prerequisites

The pinned virglrenderer source requires `import('python').find_installation('python3', modules: ['yaml'])` in `src/gallium/meson.build`. The workflow installs PyYAML in its build virtual environment. The earlier clean run at https://github.com/msx98-agent/LinuxRunner/actions/runs/44981228129 demonstrated that libepoxy configured and built but virglrenderer stopped with `ERROR: python3 is missing modules: yaml`. Graphics configuration output and Meson logs are now retained instead of redirected away. Smaller libraries build before ANGLE so missing prerequisites fail early.
