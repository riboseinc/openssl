/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sm2.h>
#include <openssl/evp.h>

static BIGNUM *compute_msg_hash(const EVP_MD *digest,
                                const EC_KEY *key,
                                const char *user_id,
                                const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t za[md_size];
    BIGNUM *e = NULL;

    if (SM2_compute_za(za, digest, user_id, key) == 0)
        goto done;

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, za, md_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, msg, msg_len) == 0)
        goto done;

    // reuse za buffer to hold H(ZA || M)
    if (EVP_DigestFinal(hash, za, NULL) == 0)
        goto done;

    e = BN_bin2bn(za, md_size, NULL);

 done:
    EVP_MD_CTX_free(hash);
    return e;
}

ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id, const uint8_t *msg, size_t msg_len)
{
    ECDSA_SIG *sig = NULL;
    BIGNUM *k = BN_new();
    BIGNUM *rk = BN_new();
    BIGNUM *e = NULL;
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    EC_POINT *kG = EC_POINT_new(group);

    /*
       A1: set M~=ZA || M
       A2: calculate e=Hv(M~)
       A3: pick a random number k in [1, n-1] via a random number generator
       A4: calculate the elliptic curve point (x1, y1)=[k]G
       A5: calculate r=(e+x1) modn, return to A3 if r=0 or r+k=n
       A6: calculate s=((1+dA)^(-1)*(k-r*dA)) modn, return to A3 if s=0
       A7: the digital signature of M is (r, s)
     */

    e = compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL)
        goto done;

    for (;;) {
        BN_priv_rand_range(k, order);

        if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) == 0)
            goto done;

        if (EC_POINT_get_affine_coordinates_GFp(group, kG, x1, NULL, ctx) == 0)
            goto done;

        if (BN_mod_add(r, e, x1, order, ctx) == 0)
            goto done;

        // try again if r == 0 or r+k == n
        if (BN_is_zero(r))
            continue;

        BN_add(rk, r, k);

        if (BN_cmp(rk, order) == 0)
            continue;

        BN_add(s, dA, BN_value_one());
        BN_mod_inverse(s, s, order, ctx);

        BN_mod_mul(tmp, dA, r, order, ctx);
        BN_sub(tmp, k, tmp);

        BN_mod_mul(s, s, tmp, order, ctx);

        sig = ECDSA_SIG_new();

        ECDSA_SIG_set0(sig, r, s);
        break;
    }

 done:
    BN_free(tmp);
    BN_free(e);
    BN_free(k);
    BN_free(x1);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *sig,
                  const char *user_id, const uint8_t *msg, size_t msg_len)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *pt = EC_POINT_new(group);

    BIGNUM *t = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *e = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    /*
       B1: verify whether r' in [1,n-1], verification failed if not
       B2: vefify whether s' in [1,n-1], verification failed if not
       B3: set M'~=ZA || M'
       B4: calculate e'=Hv(M'~)
       B5: calculate t = (r' + s') modn, verification failed if t=0
       B6: calculate the point (x1', y1')=[s']G + [t]PA
       B7: calculate R=(e'+x1') modn, verfication pass if yes, otherwise failed
     */

    e = compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL)
        goto done;

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0)
        goto done;
    if (BN_cmp(s, BN_value_one()) < 0)
        goto done;

    if (BN_cmp(order, r) <= 0)
        goto done;
    if (BN_cmp(order, s) <= 0)
        goto done;

    if (BN_mod_add(t, r, s, order, ctx) == 0)
        goto done;

    if (BN_is_zero(t) == 1)
        goto done;

    if (EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, pt, x1, NULL, ctx) == 0)
        goto done;

    if (BN_mod_add(t, e, x1, order, ctx) == 0)
        goto done;

    if (BN_cmp(r, t) == 0)
        rc = 1;

 done:
    BN_free(e);
    BN_free(t);
    BN_free(x1);
    BN_CTX_free(ctx);
    return rc;
}
