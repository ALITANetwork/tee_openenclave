// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openenclave/internal/hostresolver.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oe_u.h"

int oe_resolve_getaddrinfo(
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

void oe_resolve_freeaddrinfo(struct addrinfo* res)
{
    if (res)
        freeaddrinfo(res);
}

int oe_resolve_getnameinfo(
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

int oe_resolve_shutdown(int* err)
{
    OE_UNUSED(err);

    /* ATTN: implement this. */
    return 0;
}
