// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/sys/utsname.h>
#include "oe_t.h"

int oe_uname(struct oe_utsname* buf)
{
    int ret = -1;

    if (oe_posix_uname(&ret, (struct utsname*)buf, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}
