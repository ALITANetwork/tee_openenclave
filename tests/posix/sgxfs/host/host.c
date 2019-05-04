// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_sgxfs_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(sgxfs)\n");
        return 2; // SKIP_RETURN_CODE
    }

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TMP_DIR\n", argv[0]);
        return 1;
    }

    const char* enclave_path = argv[1];
    const char* tmp_dir = argv[2];

    r = oe_create_test_sgxfs_enclave(
        enclave_path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_sgxfs(enclave, tmp_dir);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (sgxfs)\n");

    return 0;
}
