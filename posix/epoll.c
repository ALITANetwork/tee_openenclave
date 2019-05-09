// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/posix/fdtable.h>

#include "posix_t.h"

int oe_epoll_create(int size)
{
    int ret = -1;
    int epfd = -1;
    oe_device_t* device = NULL;
    oe_device_t* epoll = NULL;

    if (!(device = oe_get_device(OE_DEVID_HOSTEPOLL, OE_DEVICE_TYPE_EPOLL)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(epoll = OE_CALL_EPOLL(epoll_create, device, size)))
        OE_RAISE_ERRNO(oe_errno);

    if ((epfd = oe_fdtable_assign(epoll)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = 0;
    epoll = NULL;

done:

    if (epoll)
        OE_CALL_BASE(close, epoll);

    return ret;
}

int oe_epoll_create1(int flags)
{
    int epfd = -1;
    oe_device_t* device = NULL;
    oe_device_t* epoll = NULL;

    if (!(device = oe_get_device(OE_DEVID_HOSTEPOLL, OE_DEVICE_TYPE_EPOLL)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(epoll = OE_CALL_EPOLL(epoll_create1, device, flags)))
        OE_RAISE_ERRNO(oe_errno);

    if ((epfd = oe_fdtable_assign(epoll)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    epoll = NULL;

done:

    if (epoll)
        OE_CALL_BASE(close, epoll);

    return epfd;
}

int oe_epoll_ctl(int epfd, int op, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* epoll;

    oe_errno = 0;

    if (!(epoll = oe_fdtable_get(epfd, OE_DEVICE_TYPE_EPOLL)))
        OE_RAISE_ERRNO(OE_EBADF);

    ret = OE_CALL_EPOLL(epoll_ctl, epoll, op, fd, event);

done:
    return ret;
}

int oe_epoll_wait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    int ret = -1;
    oe_device_t* epoll;

    if (!(epoll = oe_fdtable_get(epfd, OE_DEVICE_TYPE_EPOLL)))
        OE_RAISE_ERRNO(OE_EBADF);

    ret = OE_CALL_EPOLL(epoll_wait, epoll, events, maxevents, timeout);

done:

    return ret;
}

int oe_epoll_pwait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout,
    const oe_sigset_t* sigmask)
{
    int ret = -1;

    if (sigmask)
        OE_RAISE_ERRNO(OE_ENOTSUP);

    ret = oe_epoll_wait(epfd, events, maxevents, timeout);

done:
    return ret;
}

int oe_epoll_wake(void)
{
    int ret = -1;
    int retval;

    if (oe_posix_epoll_wake_ocall(&retval) != OE_OK)
        OE_RAISE_ERRNO(oe_errno);

    ret = retval;

done:

    return ret;
}
