// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/posix/resolver.h>
#include <openenclave/internal/trace.h>

static size_t _resolver_table_len = 3;
static oe_resolver_t* _resolver_table[3] = {0}; // At most 3

/* Called by the public oe_load_module_hostresolver() function. */
int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver)
{
    int ret = -1;

    if (presolver == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (resolver_priority >= (int)_resolver_table_len)
        OE_RAISE_ERRNO(OE_EINVAL);

    _resolver_table[resolver_priority] = presolver;

    ret = 0;
done:
    return ret;
}

int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res_out)
{
    int ret = OE_EAI_FAIL;
    size_t i;

    if (res_out)
        *res_out = NULL;

    /* Try each resolver in the table. */
    for (i = 0; i < _resolver_table_len; i++)
    {
        if (_resolver_table[i])
        {
            struct oe_addrinfo* p;

            if ((*_resolver_table[i]->ops->getaddrinfo)(
                    _resolver_table[i], node, service, hints, &p) == 0)
            {
                *res_out = p;
                ret = 0;
                goto done;
            }
        }
    }

done:

    return ret;
}

void oe_freeaddrinfo(struct oe_addrinfo* res)
{
    struct oe_addrinfo* p;

    for (p = res; p;)
    {
        struct oe_addrinfo* next = p->ai_next;

        oe_free(p->ai_addr);
        oe_free(p->ai_canonname);
        oe_free(p);

        p = next;
    }
}

int oe_getnameinfo(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)

{
    size_t resolver_idx = 0;
    ssize_t ret = -1;

    for (resolver_idx = 0; resolver_idx < _resolver_table_len; resolver_idx++)
    {
        if (_resolver_table[resolver_idx] != NULL)
        {
            ret = (*_resolver_table[resolver_idx]->ops->getnameinfo)(
                _resolver_table[resolver_idx],
                sa,
                salen,
                host,
                hostlen,
                serv,
                servlen,
                flags);
            if (ret == 0)
                goto done;
        }
    }

done:
    return (int)ret;
}
