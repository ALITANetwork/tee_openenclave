// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "pingpong_t.h"
#include <string.h>

extern "C" int oe_host_write(int device, const char* str, size_t len);

void Ping(const char* in, char* out)
{
    oe_host_write(0, "ping\n", strlen("ping\n"));
    Pong(in, out);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */
