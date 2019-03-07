/*
 * hash.c: support functions for tb_hash_t type
 *
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <safe_lib.h>
#include <openssl/evp.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"

/*
 * are_hashes_equal
 *
 * compare whether two hash values are equal.
 *
 */
bool are_hashes_equal(const tb_hash_t *hash1, const tb_hash_t *hash2,
		      uint16_t hash_alg)
{
    int diff;
    errno_t err;
    rsize_t len;

    if ( ( hash1 == NULL ) || ( hash2 == NULL ) )
        return false;

    switch ( hash_alg ) {
        case TB_HALG_SHA1:
            len = SHA1_LENGTH;
            break;
        case TB_HALG_SHA256:
            len = SHA256_LENGTH;
            break;
        case TB_HALG_SM3:
            len = SM3_LENGTH;
            break;
        case TB_HALG_SHA384:
            len = SHA384_LENGTH;
            break;
        case TB_HALG_SHA512:
            len = SHA512_LENGTH;
            break;
        default:
            return false;
    }

    err = memcmp_s(hash1, sizeof(tb_hash_t), hash2, len, &diff);
    if ( err )
        return false;

    return !diff;
}

/*
 * hash_buffer
 *
 * hash the buffer according to the algorithm
 *
 */
bool hash_buffer(const unsigned char* buf, size_t size, tb_hash_t *hash,
		 uint16_t hash_alg)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    bool ret = false;

    if ( hash == NULL )
        return false;

    ctx = EVP_MD_CTX_create();
    if ( ctx == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 ) {
        md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha1, NULL);
        ret = true;
    }
    else if (hash_alg == TB_HALG_SHA256) {
        md = EVP_sha256();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha256, NULL);
        ret = true;
    }
    else if (hash_alg == TB_HALG_SHA384) {
        md = EVP_sha384();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, size);
        EVP_DigestFinal(ctx, hash->sha384, NULL);
        ret = true;
    }

    EVP_MD_CTX_destroy(ctx);

    return ret;
}

/*
 * extend_hash
 *
 * perform "extend" of two hashes (i.e. hash1 = SHA(hash1 || hash2)
 *
 */
bool extend_hash(tb_hash_t *hash1, const tb_hash_t *hash2, uint16_t hash_alg)
{
    uint8_t buf[2*sizeof(tb_hash_t)];
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    bool ret = false;

    if ( hash1 == NULL || hash2 == NULL )
        return false;

    ctx = EVP_MD_CTX_create();
    if ( ctx == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 ) {
        memcpy_s(buf, sizeof(buf), &(hash1->sha1), sizeof(hash1->sha1));
        memcpy_s(buf + sizeof(hash1->sha1), sizeof(buf) - sizeof(hash1->sha1),
                 &(hash2->sha1), sizeof(hash1->sha1));
        md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, 2*sizeof(hash1->sha1));
        EVP_DigestFinal(ctx, hash1->sha1, NULL);
        ret = true;
    }
    else if (hash_alg == TB_HALG_SHA256) {
        memcpy_s(buf, sizeof(buf), &(hash1->sha256), sizeof(hash1->sha256));
        memcpy_s(buf + sizeof(hash1->sha256), sizeof(buf) - sizeof(hash1->sha256),
                 &(hash2->sha256), sizeof(hash1->sha256));
        md = EVP_sha256();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buf, 2*sizeof(hash1->sha256));
        EVP_DigestFinal(ctx, hash1->sha256, NULL);
        ret = true;
    }

    EVP_MD_CTX_destroy(ctx);

    return ret;
}

void print_hash(const tb_hash_t *hash, uint16_t hash_alg)
{
    unsigned int hash_size = get_hash_size(hash_alg);
    unsigned int i;
    const uint8_t *b = (const uint8_t *)hash;

    if ( hash == NULL )
        return;

    switch (hash_alg) {
        case TB_HALG_SHA1_LG:
        case TB_HALG_SHA1:
        case TB_HALG_SHA256:
        case TB_HALG_SM3:
        case TB_HALG_SHA384:
        case TB_HALG_SHA512:
            break;
        default:
            return;
    }

    for (i = 0; i < hash_size - 1; ++i)
        printf("%02x ", b[i]);

    printf("%02x\n", b[i]);
}

void copy_hash(tb_hash_t *dest_hash, const tb_hash_t *src_hash,
               uint16_t hash_alg)
{
    unsigned int len;

    if ( dest_hash == NULL || src_hash == NULL ) {
        printf("hash copy: hashes are NULL\n");
        return;
    }

    len = get_hash_size(hash_alg);
    if ( len > 0 )
        memcpy_s(dest_hash, sizeof(tb_hash_t), src_hash, len);
    else
        printf("unsupported hash alg (%u)\n", hash_alg);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
