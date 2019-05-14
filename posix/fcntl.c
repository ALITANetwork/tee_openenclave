// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/trace.h>
#include "mount.h"
#include "posix_t.h"

int __oe_fcntl(int fd, int cmd, uint64_t arg)
{
    int ret = -1;
    oe_device_t* device;

    if (!(device = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE)))
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = OE_CALL_BASE(fcntl, device, cmd, arg);

done:
    return ret;
}

int oe_open(const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;
    int fd;
    oe_device_t* fs;
    oe_device_t* file = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (!(file = OE_CALL_FS(open, fs, filepath, flags, mode)))
        OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s", pathname);

    if ((fd = oe_fdtable_assign(file)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = fd;
    file = NULL;

done:

    if (file)
        OE_CALL_BASE(close, file);

    return ret;
}

int oe_open_d(uint64_t devid, const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;
    oe_device_t* file = NULL;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_open(pathname, flags, mode);
    }
    else
    {
        oe_device_t* dev = oe_get_device(devid, OE_DEVICE_TYPE_FILESYSTEM);

        if (!dev)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (!(file = OE_CALL_FS(open, dev, pathname, flags, mode)))
            OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s mode=%u", pathname, mode);

        if ((ret = oe_fdtable_assign(file)) == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    file = NULL;

done:

    if (file)
        OE_CALL_BASE(close, file);

    return ret;
}
