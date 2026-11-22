#include "ZSignBridge.h"
#include "common.h"
#include "mach-o.h"
#include "openssl.h"
#include "macho.h"
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>

ZSignAsset::~ZSignAsset()
{
    fprintf(stderr, "ZSignAsset::~ZSignAsset: clearing key material\n");
    EVP_PKEY_free(static_cast<EVP_PKEY *>(m_evpPKey));
    X509_free(static_cast<X509 *>(m_x509Cert));
    sk_X509_pop_free(static_cast<STACK_OF(X509) *>(m_caCerts), X509_free);
    fprintf(stderr, "ZSignAsset::~ZSignAsset: released\n");
}

bool ZSignAsset::InitMemoryPKCS12(const uint8_t *bytes, size_t length, const char *password)
{
    fprintf(stderr, "ZSignAsset::InitMemoryPKCS12: checking identity\n");
    static auto *defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
    static auto *legacyProvider = OSSL_PROVIDER_load(nullptr, "legacy");
    (void)legacyProvider;
    if (!defaultProvider || !bytes || !length || length > 1024 * 1024 || !password) {
        fprintf(stderr, "ZSignAsset::InitMemoryPKCS12: invalid input\n");
        return false;
    }
    const uint8_t *cursor = bytes;
    auto *archive = d2i_PKCS12(nullptr, &cursor, static_cast<long>(length));
    EVP_PKEY *key = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *chain = nullptr;
    bool parsed = archive && cursor == bytes + length && PKCS12_parse(archive, password, &key, &cert, &chain) == 1;
    PKCS12_free(archive);
    m_evpPKey = key;
    m_x509Cert = cert;
    m_caCerts = chain;
    ERR_clear_error();
    if (!parsed || !cert || !key || X509_check_private_key(cert, key) != 1 || !GetCertSubjectCN(cert, m_strSubjectCN)) {
        ERR_clear_error();
        fprintf(stderr, "ZSignAsset::InitMemoryPKCS12: missing or unreadable identity\n");
        return false;
    }
    char team[11] = {};
    int size = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_organizationalUnitName, team, sizeof(team));
    m_strTeamId.assign(team, strnlen(team, sizeof(team)));
    bool validTeam = size == 10 && m_strTeamId.size() == 10 && m_strTeamId.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == string::npos;
    m_bSingleBinary = true;
    fprintf(stderr, "ZSignAsset::InitMemoryPKCS12: %s\n", validTeam ? "identity accepted" : "missing or invalid team ID");
    return validTeam;
}

bool LRZSignValidateIdentity(const uint8_t *p12, size_t length, const char *password)
{
    fprintf(stderr, "LRZSignValidateIdentity: starting\n");
    ZSignAsset asset;
    bool valid = asset.InitMemoryPKCS12(p12, length, password);
    fprintf(stderr, "LRZSignValidateIdentity: %s\n", valid ? "valid" : "invalid");
    return valid;
}

static int Inspect(FILE *file)
{
    fprintf(stderr, "ZSignBridge.Inspect: validating Mach-O layout\n");
    struct stat info = {};
    mach_header_64 header = {};
    if (fstat(fileno(file), &info) || !S_ISREG(info.st_mode) || info.st_size > 256 * 1024 * 1024 || fread(&header, sizeof(header), 1, file) != 1) {
        fprintf(stderr, "ZSignBridge.Inspect.file: invalid input\n");
        return LRZSignInvalid;
    }
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 || (header.filetype != MH_EXECUTE && header.filetype != MH_DYLIB && header.filetype != MH_BUNDLE)) {
        fprintf(stderr, "ZSignBridge.Inspect.header: unsupported Mach-O\n");
        return LRZSignInvalid;
    }
    size_t end = sizeof(header) + static_cast<size_t>(header.sizeofcmds);
    size_t fileSize = static_cast<size_t>(info.st_size);
    if (end > fileSize || header.sizeofcmds > 1024 * 1024) {
        fprintf(stderr, "ZSignBridge.Inspect.commands: invalid bounds\n");
        return LRZSignInvalid;
    }
    size_t offset = sizeof(header);
    size_t firstSection = fileSize;
    bool hasText = false, hasLinkEdit = false, ios = false, encrypted = false, signature = false;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        load_command cmd = {};
        if (end - offset < sizeof(cmd) || fseek(file, static_cast<long>(offset), SEEK_SET) || fread(&cmd, sizeof(cmd), 1, file) != 1 || cmd.cmdsize < sizeof(cmd) || cmd.cmdsize % 8 || cmd.cmdsize > end - offset) {
            fprintf(stderr, "ZSignBridge.Inspect.command: invalid load command\n");
            return LRZSignInvalid;
        }
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            codesignature_command sig = {};
            bool read = cmd.cmdsize == sizeof(sig) && !fseek(file, static_cast<long>(offset), SEEK_SET) && fread(&sig, sizeof(sig), 1, file) == 1;
            if (signature || !read || sig.dataoff < end || sig.dataoff > fileSize || sig.datasize > fileSize - sig.dataoff || sig.datasize == 0) {
                fprintf(stderr, "ZSignBridge.Inspect.signature: invalid signature command; leaving input unchanged\n");
                return LRZSignInvalid;
            }
            signature = true;
        } else if (cmd.cmd == LC_SEGMENT_64) {
            segment_command_64 seg = {};
            bool read = cmd.cmdsize >= sizeof(seg) && !fseek(file, static_cast<long>(offset), SEEK_SET) && fread(&seg, sizeof(seg), 1, file) == 1;
            if (!read || !memchr(seg.segname, 0, sizeof(seg.segname)) || seg.nsects > (cmd.cmdsize - sizeof(seg)) / sizeof(section_64) || seg.fileoff > fileSize || seg.filesize > fileSize - seg.fileoff) {
                fprintf(stderr, "ZSignBridge.Inspect.segment: invalid segment\n");
                return LRZSignInvalid;
            }
            hasLinkEdit |= !strcmp(seg.segname, "__LINKEDIT");
            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section_64 sec = {};
                if (fread(&sec, sizeof(sec), 1, file) != 1 || !memchr(sec.sectname, 0, sizeof(sec.sectname))) {
                    fprintf(stderr, "ZSignBridge.Inspect.section: invalid section\n");
                    return LRZSignInvalid;
                }
                if (sec.offset > 0) firstSection = min(firstSection, static_cast<size_t>(sec.offset));
                if (!strcmp(seg.segname, "__TEXT") && !strcmp(sec.sectname, "__text")) hasText = sec.offset >= end && sec.offset < fileSize;
                if (!strcmp(seg.segname, "__TEXT") && !strcmp(sec.sectname, "__info_plist") && (sec.offset > fileSize || sec.size > fileSize - sec.offset)) {
                    fprintf(stderr, "ZSignBridge.Inspect.infoPlist: invalid bounds\n");
                    return LRZSignInvalid;
                }
            }
        } else if (cmd.cmd == LC_ENCRYPTION_INFO || cmd.cmd == LC_ENCRYPTION_INFO_64) {
            encryption_info_command enc = {};
            if (cmd.cmdsize < sizeof(enc) || fseek(file, static_cast<long>(offset), SEEK_SET) || fread(&enc, sizeof(enc), 1, file) != 1) {
                fprintf(stderr, "ZSignBridge.Inspect.encryption: invalid command\n");
                return LRZSignInvalid;
            }
            encrypted |= enc.cryptid != 0;
        } else if (cmd.cmd == 0x32) {
            uint32_t platform = 0;
            if (cmd.cmdsize < 24 || fread(&platform, sizeof(platform), 1, file) != 1) {
                fprintf(stderr, "ZSignBridge.Inspect.platform: invalid command\n");
                return LRZSignInvalid;
            }
            ios |= platform == 2;
        } else if (cmd.cmd == LC_VERSION_MIN_IPHONEOS) {
            ios = true;
        } else if (cmd.cmd == LC_SEGMENT) {
            fprintf(stderr, "ZSignBridge.Inspect.segment32: unsupported segment\n");
            return LRZSignInvalid;
        }
        offset += cmd.cmdsize;
    }
    fprintf(stderr, "ZSignBridge.Inspect.commands.end: complete\n");
    if (offset == end && signature) {
        fprintf(stderr, "ZSignBridge.Inspect: preserving existing signature without judging platform trust\n");
        return LRZSignPreserved;
    }
    bool canSign = offset == end && ios && !encrypted && hasText && hasLinkEdit && firstSection >= end + sizeof(codesignature_command);
    fprintf(stderr, "ZSignBridge.Inspect: %s\n", canSign ? "unsigned iOS binary accepted" : "unsupported unsigned binary");
    return canSign ? LRZSignUnsigned : LRZSignInvalid;
}

int LRZSignInspect(const char *path)
{
    fprintf(stderr, "LRZSignInspect: starting\n");
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "LRZSignInspect.open: failed (%d)\n", errno);
        return LRZSignInvalid;
    }
    FILE *file = fdopen(fd, "rb");
    int result = file ? Inspect(file) : LRZSignInvalid;
    if (file) fclose(file);
    else close(fd);
    fprintf(stderr, "LRZSignInspect: status %d\n", result);
    return result;
}

int LRZSignTrustedBinaryCopy(const char *path, const char *identifier, const uint8_t *p12, size_t length, const char *password)
{
    fprintf(stderr, "LRZSignTrustedBinaryCopy: checking staging copy\n");
    int status = LRZSignInspect(path);
    if (status != LRZSignUnsigned) {
        fprintf(stderr, "LRZSignTrustedBinaryCopy.preflight: unchanged (%d)\n", status);
        return status;
    }
    static mutex lock;
    lock_guard<mutex> serialized(lock);
    ZSignAsset asset;
    if (!asset.InitMemoryPKCS12(p12, length, password)) {
        fprintf(stderr, "LRZSignTrustedBinaryCopy.identity: rejected\n");
        return LRZSignBadIdentity;
    }
    ZMachO binary;
    bool signedOK = binary.Init(path) && binary.Sign(&asset, true, identifier, "", "", "");
    fprintf(stderr, "LRZSignTrustedBinaryCopy.sign: %s\n", signedOK ? "signed" : "failed");
    return signedOK ? LRZSignCompleted : LRZSignFailed;
}
