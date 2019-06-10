// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>

#include <tee_internal_api.h>

oe_result_t oe_get_entropy(void* output, size_t len)
{
    if (len > OE_UINT32_MAX)
        return OE_OUT_OF_BOUNDS;

    TEE_GenerateRandom(output, (uint32_t)len);

    return OE_OK;
}
