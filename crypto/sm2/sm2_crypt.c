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
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) =
{
ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
        ASN1_SIMPLE(SM2_Ciphertext, C2,
                        ASN1_OCTET_STRING),} ASN1_SEQUENCE_END(SM2_Ciphertext)
IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

static int EC_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    int field_size;

    EC_GROUP_get_curve_GFp(group, p, a, b, NULL);
    field_size = (BN_num_bits(p) + 7) / 8;

    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

int SM2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len)
{
    return 10 + 2 * EC_field_size(EC_KEY_get0_group(key)) +
        EVP_MD_size(digest) + msg_len;
}

int SM2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0;
    BIGNUM *k = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *y2 = BN_new();

    BN_CTX *ctx = BN_CTX_new();
    EVP_MD_CTX *hash = EVP_MD_CTX_new();

    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    EC_POINT *kG = EC_POINT_new(group);
    EC_POINT *kP = EC_POINT_new(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    uint8_t msg_mask[msg_len];

    const size_t field_size = EC_field_size(group);
    uint8_t x2y2[2 * field_size];
    uint8_t x2_bits[field_size];
    uint8_t y2_bits[field_size];

    const size_t C3_size = EVP_MD_size(digest);
    uint8_t C3[C3_size];

    memset(ciphertext_buf, 0, *ciphertext_len);

    BN_priv_rand_range(k, order);

    if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, kG, x1, y1, ctx) == 0)
        goto done;

    if (EC_POINT_mul(group, kP, NULL, P, k, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, kP, x2, y2, ctx) == 0)
        goto done;

    BN_bn2binpad(x2, x2_bits, field_size);
    BN_bn2binpad(y2, y2_bits, field_size);

    memcpy(x2y2, x2_bits, field_size);
    memcpy(x2y2 + field_size, y2_bits, field_size);

    // This happens to match the KDF used in SM2
    if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)
        == 0)
        goto done;

    for (size_t i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2_bits, field_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, msg, msg_len) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, y2_bits, field_size) == 0)
        goto done;

    if (EVP_DigestFinal(hash, C3, NULL) == 0)
        goto done;

    struct SM2_Ciphertext_st ctext_struct;
    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size);
    ctext_struct.C2 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len);

    *ciphertext_len = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);

    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);

    rc = 1;

 done:
    BN_free(k);
    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int SM2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
    int rc = 0;

    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    const size_t field_size = EC_field_size(group);
    uint8_t x2y2[2 * field_size];
    uint8_t x2_bits[field_size];
    uint8_t y2_bits[field_size];
    BIGNUM *x2 = BN_new();
    BIGNUM *y2 = BN_new();
    const size_t hash_size = EVP_MD_size(digest);
    uint8_t computed_C3[hash_size];

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    const uint8_t *C2 = sm2_ctext->C2->data;
    const int msg_len = sm2_ctext->C2->length;
    uint8_t msg_mask[msg_len];

    const uint8_t *C3 = sm2_ctext->C3->data;

    if (sm2_ctext->C3->length != hash_size)
        goto done;

    EVP_MD_CTX *hash = EVP_MD_CTX_new();

    if (sm2_ctext == NULL)
        goto done;

    C1 = EC_POINT_new(group);
    if (C1 == NULL)
        goto done;

    if (EC_POINT_set_affine_coordinates_GFp
        (group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx) == 0)
        goto done;

    if (EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx) ==
        0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, C1, x2, y2, ctx) == 0)
        goto done;

    BN_bn2binpad(x2, x2_bits, field_size);
    BN_bn2binpad(y2, y2_bits, field_size);

    memcpy(x2y2, x2_bits, field_size);
    memcpy(x2y2 + field_size, y2_bits, field_size);

    if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)
        == 0)
        goto done;

    for (size_t i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, x2_bits, field_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, ptext_buf, msg_len) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, y2_bits, field_size) == 0)
        goto done;

    if (EVP_DigestFinal(hash, computed_C3, NULL) == 0)
        goto done;

    if (memcmp(computed_C3, C3, hash_size) != 0)
        goto done;

    rc = 1;

 done:

    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    BN_free(x2);
    BN_free(y2);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);

    return rc;
}
