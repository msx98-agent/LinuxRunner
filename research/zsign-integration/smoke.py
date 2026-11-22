"""Exercise the static backend with temporary, non-Apple test fixtures on Linux."""
import os
import pathlib
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(*command, cwd=ROOT):
    print(f"zsign.smoke.run: {command[0]} {command[1]}", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def macho(platform=2, commands=b"", extra_count=0):
    print(f"zsign.smoke.macho: building fixture for platform {platform} with {extra_count} extra commands")
    pack = struct.pack
    segment = "<II16sQQQQIIII"
    section = "<16s16sQQIIIIIIII"
    code = pack(segment, 0x19, 152, b"__TEXT", 0x100000000, 4096, 0, 4096, 5, 5, 1, 0)
    code += pack(section, b"__text", b"__TEXT", 0x100000400, 4, 1024, 2, 0, 0, 0, 0, 0, 0)
    code += pack(segment, 0x19, 72, b"__LINKEDIT", 0x100001000, 4096, 4096, 16, 1, 1, 0, 0)
    code += pack("<6I", 0x32, 24, platform, 0xf0000, 0xf0000, 0) + commands
    header = pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 3 + extra_count, len(code), 0, 0)
    print("zsign.smoke.macho.end: fixture encoded")
    return (header + code).ljust(4112, b"\0")


def main():
    print("zsign.smoke: building backend", flush=True)
    run("bash", "scripts/build-zsign.sh", "linux")
    with tempfile.TemporaryDirectory(prefix="linuxrunner-zsign-") as directory:
        tmp = pathlib.Path(directory)
        run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=LinuxRunner Test CA", "-days", "1", cwd=tmp)
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=Test Signer/OU=TEST123456", cwd=tmp)
        run("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "1", "-out", "leaf.pem", "-days", "1", cwd=tmp)
        for name, args in {"fixture": [], "legacy": ["-legacy"]}.items():
            run("openssl", "pkcs12", "-export", *args, "-inkey", "leaf.key", "-in", "leaf.pem", "-certfile", "ca.pem", "-passout", "pass:test-only", "-out", name + ".p12", cwd=tmp)
        (tmp / "unsigned").write_bytes(macho())
        (tmp / "signed").write_bytes(macho(commands=struct.pack("<4I", 0x1d, 16, 4096, 16), extra_count=1))
        (tmp / "macos").write_bytes(macho(platform=1))
        (tmp / "invalid").write_bytes(b"\xcf\xfa\xed\xfe")
        (tmp / "bad-range").write_bytes(macho(commands=struct.pack("<4I", 0x1d, 16, 0xffffffff, 16), extra_count=1))
        (tmp / "symlink").symlink_to("unsigned")
        unsigned, existing = [(tmp / name).read_bytes() for name in ("unsigned", "signed")]
        run(os.getenv("CXX", "c++"), "-std=c++17", "-I" + str(ROOT / "app/LinuxRunner"), str(pathlib.Path(__file__).with_name("smoke.cpp").resolve()), str(ROOT / "build/zsign/linux/liblrzsign.a"), "-o", "smoke", cwd=tmp)
        run("./smoke", "fixture.p12", cwd=tmp)
        assert (tmp / "signed").read_bytes() == existing, "existing signature was changed"
        output = (tmp / "unsigned").read_bytes()
        assert output != unsigned
        offset = 32
        for _ in range(struct.unpack_from("<I", output, 16)[0]):
            cmd, size = struct.unpack_from("<II", output, offset)
            if cmd == 0x1d:
                start, length = struct.unpack_from("<II", output, offset + 8)
                assert start + length == len(output)
                magic, _, count = struct.unpack_from(">III", output, start)
                assert magic == 0xfade0cc0
                slots = dict(struct.unpack_from(">II", output, start + 12 + 8 * i) for i in range(count))
                cd = start + slots[0]
                cms = start + slots[0x10000]
                cms_magic, cms_size = struct.unpack_from(">II", output, cms)
                assert cms_magic == 0xfade0b01 and cms_size > 8
                cd_size = struct.unpack_from(">I", output, cd + 4)[0]
                (tmp / "cd").write_bytes(output[cd:cd + cd_size])
                (tmp / "cms").write_bytes(output[cms + 8:cms + cms_size])
                run("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", "cms", "-content", "cd", "-CAfile", "ca.pem", "-purpose", "any", "-out", os.devnull, cwd=tmp)
                break
            offset += size
        else:
            raise AssertionError("output has no signature load command")
    print("zsign.smoke.end: identity, signature preservation, input rejection and CMS verification passed")


if __name__ == "__main__":
    main()
