// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _OE_STDIO_H
#error "Please include the stdio.h from corelibc."
#endif

void test_corelibc(const char* tmp_dir)
{
    oe_enable_feature(OE_FEATURE_HOST_FILES);

    if (mount("/", "/", "hostfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    /* Create the temporary directory. */
    {
        OE_TEST(tmp_dir != NULL);
        OE_TEST(mkdir(tmp_dir, 0777) == 0);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
