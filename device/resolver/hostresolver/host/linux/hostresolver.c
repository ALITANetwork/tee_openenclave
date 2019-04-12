// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openenclave/internal/resolver.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oe_u.h"

int oe_posix_getaddrinfo_ocall(
    const char* node,
    const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res,
    int* err)
{
    int ret = getaddrinfo(node, service, hints, res);

    if (ret == EAI_SYSTEM)
    {
        if (err)
            *err = errno;

        goto done;
    }

done:
    return ret;
}

void oe_posix_freeaddrinfo_ocall(struct addrinfo* res)
{
    if (res)
        freeaddrinfo(res);
}

int oe_posix_getnameinfo_ocall(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags,
    int* err)
{
    int ret = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);

    if (ret == EAI_SYSTEM)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_shutdown_resolver_device_ocall(int* err)
{
    OE_UNUSED(err);

    /* ATTN: implement this. */
    return 0;
}
