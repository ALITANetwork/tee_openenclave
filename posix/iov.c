// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/internal/posix/iov.h>

/* Get the deflated size of the IO vector. */
size_t oe_iov_compute_size(const struct oe_iovec* iov, size_t iov_count)
{
    size_t size = 0;

    for (size_t i = 0; i < iov_count; i++)
        size += iov[i].iov_len;

    return size;
}

int oe_iov_deflate(
    const struct oe_iovec* iov,
    size_t iov_count,
    void** buf_out,
    size_t* buf_size_out)
{
    int ret = -1;
    void* buf = NULL;
    size_t buf_size = 0;

    if (buf_out)
        *buf_out = NULL;

    if (buf_size_out)
        *buf_size_out = 0;

    if (!iov || !buf_out || !buf_size_out)
        goto done;

    /* Calculate the size of the deflated buffer. */
    buf_size = oe_iov_compute_size(iov, iov_count);

    /* Allocate the output buffer. */
    if (!(buf = oe_malloc(buf_size)))
        goto done;

    /* Copy the IO vector onto the deflated buffer. */
    {
        uint8_t* p = (uint8_t*)buf;
        size_t n = buf_size;

        for (size_t i = 0; i < iov_count; i++)
        {
            const void* base = iov[i].iov_base;
            size_t len = iov[i].iov_len;

            if (len == 0)
                continue;

            if (oe_memcpy_s(p, n, base, len) != OE_OK)
                goto done;

            p += len;
            n -= len;
        }
    }

    *buf_out = buf;
    *buf_size_out = buf_size;
    buf = NULL;

    ret = 0;

done:

    if (buf)
        oe_free(buf);

    return ret;
}

int oe_iov_inflate(
    const void* buf,
    size_t buf_size,
    struct oe_iovec* iov,
    size_t iov_count)
{
    int ret = -1;
    const uint8_t* p = (const uint8_t*)buf;
    size_t n = buf_size;

    if (!buf || !iov)
        goto done;

    for (size_t i = 0; i < iov_count && n; i++)
    {
        void* base = iov[i].iov_base;
        size_t len = iov[i].iov_len;
        size_t min = (len < n) ? len : n;

        if (oe_memcpy_s(base, n, p, min) != OE_OK)
            goto done;

        p += min;
        n -= min;
    }

    /* If the buffer was not exhausted, then fail. */
    if (n != 0)
        goto done;

    ret = 0;

done:
    return ret;
}
