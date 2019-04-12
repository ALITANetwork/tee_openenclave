// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/host.h>
#include <sys/signal.h>
#include <errno.h>
#include "oe_u.h"
// clang-format on

// Poll uses much of the infrastructure from epoll.

int oe_posix_kill_ocall(int pid, int signum, int* err)

{
    int retval = -1;

    *err = 0;

    retval = kill(pid, signum);

    if (retval < 0)
    {
        if (err)
            *err = errno;
    }

    return retval;
}
