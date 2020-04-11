#include <nettle/sha2.h>
#include <nettle/sha3.h>
#include <string.h>

#define BUF_SIZE 128

void compute_sha3_256(char *digest, char *str) {
    struct sha3_256_ctx ctx = {0};
    sha3_256_init(&ctx);
    sha3_256_update(&ctx, strnlen(str, BUF_SIZE), str);
    sha3_256_digest(&ctx, SHA3_256_DIGEST_SIZE, digest);
}

void compute_sha256(char *digest, char *str) {
    struct sha256_ctx ctx = {0};
    sha256_init(&ctx);
    sha256_update(&ctx, strnlen(str, BUF_SIZE), str);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
}

void compute_hash(char *digest, char *password) {
    char sha256_dgst[BUF_SIZE + 1] = {0};
    compute_sha256(sha256_dgst, password);
    compute_sha3_256(digest, sha256_dgst);
}
