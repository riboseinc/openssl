/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM4
# include "internal/sm4.h"

static int test_sm4_ecb(void)
{
    static const uint8_t k[16] = {
       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[16] = {
       0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t expected[16] = {
       0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
       0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    // after 1,000,000 iterations
    static const uint8_t expected_iter[16] = {
       0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
       0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    SM4_KEY key;
    SM4_set_key(k, &key);

    uint8_t block[16];
    memcpy(block, input, 16);

    SM4_encrypt(block, block, &key);
    if (!TEST_mem_eq(block, 16, expected, 16))
       return 0;

    for(int i = 0; i != 999999; ++i)
       SM4_encrypt(block, block, &key);

    if (!TEST_mem_eq(block, 16, expected_iter, 16))
       return 0;

    for(int i = 0; i != 1000000; ++i)
       SM4_decrypt(block, block, &key);

    if (!TEST_mem_eq(block, 16, input, 16))
       return 0;

    return 1;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_sm4_ecb);
#endif
    return 1;
}
