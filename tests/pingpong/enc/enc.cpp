// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <string.h>
#include "pingpong_t.h"

extern "C" int oe_host_write(int device, const char* str, size_t len);

void Ping(const char* in, char* out)
{
    Pong(in, out);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */
