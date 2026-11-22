#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    LRZSignInvalid = -1,
    LRZSignFailed = -2,
    LRZSignBadIdentity = -3,
    LRZSignUnsigned = 0,
    LRZSignPreserved = 1,
    LRZSignCompleted = 2,
};

#ifdef __cplusplus
extern "C" {
#endif
bool LRZSignValidateIdentity(const uint8_t *p12, size_t length, const char *password);
int LRZSignInspect(const char *path);
int LRZSignTrustedBinaryCopy(const char *path, const char *identifier, const uint8_t *p12, size_t length, const char *password);
#ifdef __cplusplus
}
#endif
