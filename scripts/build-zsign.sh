#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo 'build-zsign: checking toolchain and pinned dependencies'
platform=${1:?Specify iphoneos, iphonesimulator or linux}
arch=${2:-arm64}
root=$PWD
out="$root/build/zsign/$platform"
zsign=9299685bab7ef99827e06e5dfda93af747386590
openssl=45e844fa2a14ec92d146bd8f5778ac130b6625fb
openssl_archive=f54250b21795bb01240f3f9b42c384868d04460e339e39275aaaf93487f2d903
zsign_archive=97bcc2dbbc0dc5f092dc4a33cbe1f9fdbd5c83bdc291da23db45044d4396270e
flags=()
case "$platform:$arch" in
    iphoneos:arm64) target=ios64-xcrun; flags=(-miphoneos-version-min=15.0) ;;
    iphonesimulator:arm64) target=iossimulator-arm64-xcrun; flags=(-mios-simulator-version-min=15.0) ;;
    linux:*) target=linux ;;
    *) echo 'build-zsign: unsupported platform/architecture' >&2; exit 2 ;;
esac
if [[ $target == linux ]]; then
    cxx=${CXX:-c++}
    sdk=system
else
    cxx=$(/usr/bin/xcrun --sdk "$platform" --find clang++)
    sdk=$(/usr/bin/xcrun --sdk "$platform" --show-sdk-path)
    flags+=(-isysroot "$sdk" -arch "$arch")
fi
mkdir -p "$out"
stamp=$(printf '%s\n' "$platform:$arch:$sdk" "$("$cxx" --version)" "$(shasum -a 256 "$0" app/LinuxRunner/ZSignBridge.{cpp,h})" | shasum -a 256 | cut -d ' ' -f 1)
if [[ -f $out/liblrzsign.a && -f $out/NOTICES.txt && -f $out/stamp ]] && [[ $(cat "$out/stamp") == "$stamp" ]]; then
    echo 'build-zsign: static signer is up to date'
    exit 0
fi
echo 'build-zsign: preparing static signer'
work=$(mktemp -d "$out/work.XXXXXX")
trap 'rm -rf "$work"' EXIT
download() {
    echo "build-zsign.download: fetching pinned $1"
    local repo=$1 revision=$2 digest=$3 archive="$work/${1##*/}.tar.gz"
    curl -fsSL --retry 3 -o "$archive" "https://codeload.github.com/$repo/tar.gz/$revision"
    printf '%s  %s\n' "$digest" "$archive" | shasum -a 256 -c -
    mkdir "$work/${repo##*/}"
    tar -xf "$archive" -C "$work/${repo##*/}" --strip-components=1
    echo "build-zsign.download: verified and unpacked $repo"
}
download zhlynn/zsign "$zsign" "$zsign_archive"
src="$work/zsign/src"
python3 - "$src" <<'PY'
from pathlib import Path
import sys

print("build-zsign.patch: enabling in-memory identity and mapping cleanup")
src = Path(sys.argv[1])
updates = {
    "openssl.h": [("\tZSignAsset();", "\tZSignAsset();\n\t~ZSignAsset();\n\tbool InitMemoryPKCS12(const uint8_t*, size_t, const char*);")],
    "macho.cpp": [("ZMachO::~ZMachO()\n{\n", "ZMachO::~ZMachO()\n{\n\tCloseFile();\n"), ("\treturn true;\n}\n\nvoid ZMachO::PrintInfo", "\tm_pBase = NULL;\n\tm_sSize = 0;\n\treturn true;\n}\n\nvoid ZMachO::PrintInfo")],
}
for name, edits in updates.items():
    path = src / name
    text = path.read_text()
    for old, new in edits:
        if text.count(old) != 1:
            sys.exit(f"build-zsign.patch: unexpected upstream contents in {name}")
        text = text.replace(old, new, 1)
    path.write_text(text)
path = src / "openssl.cpp"
text = path.read_text()
start = text.index("bool ZSignAsset::GenerateCMS(void*")
end = text.index("\nbool ZSignAsset::GetCMSContent", start)
cms = text[start:end]
owners = {
    "STACK_OF(X509)* otherCerts = sk_X509_new_null();": ("otherCerts", "[](STACK_OF(X509)* p) { sk_X509_pop_free(p, X509_free); }"),
    "BIO* in = BIO_new_mem_buf(strCDHashData.c_str(), (int)strCDHashData.size());": ("in", "BIO_free"),
    "CMS_ContentInfo* cms = CMS_sign(NULL, NULL, otherCerts, NULL, nFlags);": ("cms", "CMS_ContentInfo_free"),
    'ASN1_OBJECT* obj = OBJ_txt2obj("1.2.840.113635.100.9.1", 1);': ("obj", "ASN1_OBJECT_free"),
    'ASN1_OBJECT* obj2 = OBJ_txt2obj("1.2.840.113635.100.9.2", 1);': ("obj2", "ASN1_OBJECT_free"),
    "X509_ATTRIBUTE* attr = X509_ATTRIBUTE_new();": ("attr", "X509_ATTRIBUTE_free"),
    "ASN1_TYPE* type_256 = (ASN1_TYPE*)GenerateASN1Type(sha256);": ("type_256", "ASN1_TYPE_free"),
    "BIO* out = BIO_new(BIO_s_mem());": ("out", "BIO_free"),
}
for declaration, (name, deleter) in owners.items():
    if cms.count(declaration) != 1:
        sys.exit("build-zsign.patch: unexpected upstream CMS declaration")
    cms = cms.replace(declaration, f"{declaration}\n\tauto free_{name} = {deleter};\n\tunique_ptr<remove_pointer_t<decltype({name})>, decltype(free_{name})> own_{name}({name}, free_{name});")
cms = cms.replace("\tASN1_TYPE_free(type_256);\n", "").replace("\tsk_X509_pop_free(otherCerts, X509_free); // CMS_sign holds its own references\n", "")
text = text[:start] + cms + text[end:]
path.write_text("#include <type_traits>\n" + text)
print("build-zsign.patch: changes applied")
PY
download openssl/openssl "$openssl" "$openssl_archive"
echo 'build-zsign.openssl: compiling static crypto providers'
(
    cd "$work/openssl"
    if [[ $target == linux ]]; then
        unset CFLAGS
        perl Configure no-shared no-module no-tests no-apps no-docs no-dso
        make -j "$(nproc)" build_libs > "$out/openssl-build.log" 2>&1 || { tail -35 "$out/openssl-build.log" >&2; exit 1; }
    else
        export CFLAGS="${flags[0]}"
        /usr/bin/perl Configure "$target" no-shared no-module no-tests no-apps no-docs no-dso
        /usr/bin/make -j "$(sysctl -n hw.ncpu)" build_libs > "$out/openssl-build.log" 2>&1 || { tail -35 "$out/openssl-build.log" >&2; exit 1; }
    fi
)
flags+=(-I"$work/openssl/include")
echo 'build-zsign.openssl: static crypto build complete'
sources=("$root/app/LinuxRunner/ZSignBridge.cpp" "$src"/{archo,macho,openssl,signing}.cpp "$src"/common/{fs,json,log,sha,util}.cpp)
objects=()
for source in "${sources[@]}"; do
    object="$work/$(basename "$source").o"
    "$cxx" -std=c++17 -O2 -DNDEBUG -fvisibility=hidden "${flags[@]}" -I"$src" -I"$src/common" -c "$source" -o "$object"
    objects+=("$object")
done
echo 'build-zsign.objects: compilation complete'
if [[ $target == linux ]]; then
    cp "$work/openssl/libcrypto.a" "$work/liblrzsign.a"
    ar rcs "$work/liblrzsign.a" "${objects[@]}"
else
    /usr/bin/libtool -static -o "$work/liblrzsign.a" "${objects[@]}" "$work/openssl/libcrypto.a"
fi
cat "$work/zsign/LICENSE" "$work/openssl/LICENSE.txt" > "$work/NOTICES.txt"
mv "$work/liblrzsign.a" "$work/NOTICES.txt" "$out/"
printf '%s\n' "$stamp" > "$out/stamp"
echo 'build-zsign: static signer ready'
