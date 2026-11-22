#include "ZSignBridge.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

static std::vector<uint8_t> ReadIdentity(const char *path)
{
    fprintf(stderr, "smoke.ReadIdentity: reading test fixture\n");
    std::ifstream stream(path, std::ios::binary);
    std::vector<uint8_t> result{std::istreambuf_iterator<char>(stream), {}};
    fprintf(stderr, "smoke.ReadIdentity.end: read %zu bytes\n", result.size());
    return result;
}

int main()
{
    fprintf(stderr, "smoke.main: starting native signer assertions\n");
    auto identity = ReadIdentity("fixture.p12");
    auto legacy = ReadIdentity("legacy.p12");
    assert(!LRZSignValidateIdentity(identity.data(), identity.size(), "wrong"));
    assert(LRZSignValidateIdentity(identity.data(), identity.size(), "test-only"));
    assert(LRZSignValidateIdentity(legacy.data(), legacy.size(), "test-only"));
    assert(LRZSignInspect("invalid") == LRZSignInvalid);
    assert(LRZSignInspect("bad-range") == LRZSignInvalid);
    assert(LRZSignInspect("macos") == LRZSignInvalid);
    assert(LRZSignInspect("symlink") == LRZSignInvalid);
    assert(LRZSignInspect("unsigned") == LRZSignUnsigned);
    assert(LRZSignTrustedBinaryCopy("signed", "dev.test.bin", nullptr, 0, nullptr) == LRZSignPreserved);
    assert(LRZSignTrustedBinaryCopy("unsigned", "dev.test.bin", identity.data(), identity.size(), "test-only") == LRZSignCompleted);
    assert(LRZSignTrustedBinaryCopy("unsigned", "dev.test.bin", nullptr, 0, nullptr) == LRZSignPreserved);
    fprintf(stderr, "smoke.main.end: all native signer assertions passed\n");
    return 0;
}
