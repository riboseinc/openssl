/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sm2.h>

ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id,
                       const uint8_t *msg,
                       size_t msg_len)
   {
   return NULL;
   }

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const char *user_id,
                  const uint8_t *msg,
                  size_t msg_len)
   {
   return 1;
   }

