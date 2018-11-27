#include "common.h"
#include "ec.h"
#include "hash.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "stdbool.h"

static EC_KEY *key = NULL;
static bool isInit = false;
// SRC: https://github.com/openssl/openssl/blob/57d7b988b498ed34e98d1957fbbded8342f2a952/test/sm2_internal_test.c#L229
static const char *privkey_hex = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";

int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {

    if (!isInit) {
        key = bbp_ec_new_keypair_from_hex(privkey_hex);
        // Previous call should never fail
        assert(key);
        isInit = true;
    }

    /* We need
     *   32 bytes for sig->r
     *   32 bytes for sig->s
     *   At least 1 byte for message whose signature we are trying to forge
     */
    if (Size < 65) {
        return 0;
    }

    ECDSA_SIG *signature = ECDSA_SIG_new();
    if (!signature) {
        goto done;
    }
    BIGNUM *sig_r = NULL;
    BIGNUM *sig_s = NULL;
    uint8_t digest[32] = {0};
    int verified = 0;
    int r;

    sig_r = BN_bin2bn(Data, 32, NULL);
    Data += 32;
    Size -= 32;
    sig_s = BN_bin2bn(Data, 32, NULL);
    Data += 32;
    Size -= 32;

    /* The r and s values can be set by calling ECDSA_SIG_set0() and passing
     * the new values for r and s as parameters to the function. Calling this
     * function transfers the memory management of the values to the ECDSA_SIG
     * object, and therefore the values that have been passed in should not be
     * freed directly after this function has been called.
     *
     * ECDSA_SIG_set0() returns 1 on success or 0 on failure.
     */
    if (!ECDSA_SIG_set0(signature, sig_r, sig_s)) {
        BN_free(sig_r);
        BN_free(sig_s);
        goto done;
    }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    printf("r: %s\n", BN_bn2hex(sig_r));
    printf("s: %s\n", BN_bn2hex(sig_s));
#endif

    const uint8_t *message = Data;

    // Obtain message digest
    bbp_sha256(digest, message, Size);

    // Assert on successful verification of forged signature
    verified = ECDSA_do_verify(digest, sizeof(digest), signature, key);
    assert(verified != 1);

done:
    ECDSA_SIG_free(signature);
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_get_state();
    return 1;
}
