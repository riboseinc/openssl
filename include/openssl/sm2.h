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

#ifndef HEADER_SM2_H
# define HEADER_SM2_H

# include <openssl/ec.h>

int SM2_compute_za(uint8_t *out,
                   const EVP_MD *digest,
                   const char *user_id, const EC_KEY *key);

/*
* SM2 signatures
*/
ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id, const uint8_t *msg, size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const char *user_id, const uint8_t *msg, size_t msg_len);

/*
* SM2 encryption
*/
int SM2_ciphertext_size(const EC_KEY *key,
                        const EVP_MD *digest, size_t msg_len);

int SM2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int SM2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

#endif
