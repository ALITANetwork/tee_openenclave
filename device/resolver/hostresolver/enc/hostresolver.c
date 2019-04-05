// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/internal/hostresolver.h>
#include <openenclave/internal/resolver.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/deepcopy.h>
#include "oe_t.h"

// The host resolver is not actually a device in the file descriptor sense.

extern oe_structure_t __oe_addrinfo_structure;

// clang-format off
static oe_pointer_field_t _oe_addrinfo_fields[] = 
{
    {
        .field_offset = OE_OFFSETOF(struct oe_addrinfo, ai_addr),
        .field_size = OE_SIZEOF(struct oe_addrinfo, ai_addr),
        .elem_size = sizeof(uint8_t),
        .count_offset = OE_OFFSETOF(struct oe_addrinfo, ai_addrlen),
        .count_value = OE_SIZEOF(struct oe_addrinfo, ai_addrlen),
    },
    {
        .field_offset = OE_OFFSETOF(struct oe_addrinfo, ai_next),
        .field_size = OE_SIZEOF(struct oe_addrinfo, ai_next),
        .elem_size = sizeof(struct oe_addrinfo),
        .count_offset = OE_SIZE_MAX,
        .count_value = 1,
    },
    {
        .field_offset = OE_OFFSETOF(struct oe_addrinfo, ai_canonname),
        .field_size = OE_SIZEOF(struct oe_addrinfo, ai_canonname),
        .elem_size = sizeof(char),
        .count_offset = OE_SIZE_MAX,
        .count_value = OE_SIZE_MAX,
    },
};
// clang-format on

// clang-format off
oe_structure_t __oe_addrinfo_structure = 
{
    .struct_size = sizeof(struct oe_addrinfo),
    _oe_addrinfo_fields,
    OE_COUNTOF(_oe_addrinfo_fields),
};
// clang-format on

/*
**==============================================================================
**
** hostresolv operations:
**
**==============================================================================
*/

#define RESOLV_MAGIC 0x536f636b

typedef struct _resolv
{
    struct _oe_resolver base;
    uint32_t magic;
} resolv_t;

static resolv_t* _cast_resolv(const oe_resolver_t* device)
{
    resolv_t* resolv = (resolv_t*)device;

    if (resolv == NULL || resolv->magic != RESOLV_MAGIC)
        return NULL;

    return resolv;
}

static resolv_t _hostresolv;

static ssize_t _hostresolv_getnameinfo(
    oe_resolver_t* dev,
    const struct oe_sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    int ret = OE_EAI_FAIL;

    OE_UNUSED(dev);

    oe_errno = 0;

    if (oe_resolve_getnameinfo(
            &ret,
            (const struct sockaddr*)sa,
            salen,
            host,
            hostlen,
            serv,
            servlen,
            flags,
            &oe_errno) != OE_OK)
    {
        goto done;
    }

done:

    return ret;
}

//
// We try return the sockaddr if it fits, but if it doesn't we return
// OE_EAI_OVERFLOW and the required size. IF the buffer is overflowed the caller
// needs to try _hostresolv_getaddrinfo with a suitably reallocated buffer
//
static ssize_t _hostresolv_getaddrinfo_r(
    oe_resolver_t* resolv,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo* res_out,
    /* ATTN: change to size_t */
    ssize_t* required_size_in_out)
{
    ssize_t ret = OE_EAI_FAIL;
    int retval;
    struct oe_addrinfo* res;
    size_t required_size = 0;

    OE_UNUSED(resolv);
    OE_UNUSED(res_out);

    oe_errno = 0;

    if (oe_resolve_getaddrinfo(
            &retval,
            node,
            service,
            (const struct addrinfo*)hints,
            (struct addrinfo**)&res,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (retval != 0)
    {
        ret = retval;
        goto done;
    }

    /* Determine required buffer size (fail if caller's buffer is too small). */
    {
        if (oe_deep_size(&__oe_addrinfo_structure, res, &required_size) != 0)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (required_size > (size_t)*required_size_in_out)
        {
            *required_size_in_out = (ssize_t)required_size;
            ret = OE_EAI_OVERFLOW;
            goto done;
        }
    }

    /* Copy OCALL result to caller's buffer. */
    {
        oe_flat_allocator_t a;

        oe_flat_allocator_init(&a, res_out, required_size);

        if (oe_deep_copy(
                &__oe_addrinfo_structure, res, res_out, oe_flat_alloc, &a) != 0)
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    /* Ask host to release the result buffer. */
    if (oe_resolve_freeaddrinfo((struct addrinfo*)res) != OE_OK)
        goto done;

    ret = 0;

done:

    return ret;
}

static int _hostresolv_shutdown(oe_resolver_t* resolv_)
{
    int ret = -1;
    resolv_t* resolv = _cast_resolv(resolv_);

    oe_errno = 0;

    /* Check parameters. */
    if (!resolv_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_resolve_shutdown(&ret, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Release the resolv_ object. */
    oe_free(resolv);

    ret = 0;

done:
    return ret;
}

static oe_resolver_ops_t _ops = {.getaddrinfo_r = _hostresolv_getaddrinfo_r,
                                 .getnameinfo = _hostresolv_getnameinfo,
                                 .shutdown = _hostresolv_shutdown};

static resolv_t _hostresolv = {.base.type = OE_RESOLVER_HOST,
                               .base.size = sizeof(resolv_t),
                               .base.ops = &_ops,
                               .magic = RESOLV_MAGIC};

oe_resolver_t* oe_get_hostresolver(void)
{
    return &_hostresolv.base;
}
