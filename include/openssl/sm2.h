/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM2_H
# define HEADER_SM2_H

#include <openssl/ec.h>

int SM2_compute_za(uint8_t *out,
                   const EVP_MD *digest,
                   const char *user_id,
                   const EC_KEY *key);

ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id,
                       const uint8_t *msg,
                       size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG* signature,
                  const char *user_id,
                  const uint8_t *msg,
                  size_t msg_len);

#endif
