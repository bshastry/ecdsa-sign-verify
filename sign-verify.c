#include "common.h"
#include "ec.h"
#include "hash.h"

void signMessageDigest(ECDSA_SIG *signature, uint8_t *digest, EC_KEY *key, const uint8_t *message) {
    bbp_sha256(digest, message, strlen((const char *)message));
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    bbp_print_hex("digest: ", digest, 32);
#endif

    signature = ECDSA_do_sign(digest, sizeof(digest), key);
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));
#endif
}

int LLVMFuzzerTestOneInput(uint8_t *Data, size_t Size) {

    if (Size < 33) {
        return 0;
    }

    EC_KEY *key;
    ECDSA_SIG *signature;
    uint8_t digest[32];
    int verified;
    uint8_t *priv_bytes = malloc(32);
    memcpy(priv_bytes, Data, 32);
    Data += 32;
    Size -= 32;

    const char *message = (const char *)Data;
    if (strlen(message) < 1 || strlen(message) != Size - 1) {
        return 0;
    }

    key = bbp_ec_new_keypair(priv_bytes);
    if (!key) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        printf("Unable to create keypair\n");
#endif
        return 0;
    }

    signMessageDigest(signature, (uint8_t *)&digest[0], key,
                      (const uint8_t *)message);
    assert(signature);
    verified = ECDSA_do_verify(digest, sizeof(digest), signature, key);
    assert(verified == 1);

    ECDSA_SIG_free(signature);
    EC_KEY_free(key);

    return 0;
}
