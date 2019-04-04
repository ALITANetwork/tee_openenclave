/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/deepcopy.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/hostresolver.h>
#include <openenclave/internal/tests.h>

#include <resolver_test_t.h>
#include <stdio.h>
#include <string.h>
#include "../utils.h"

size_t oe_debug_malloc_check();

struct addrinfo;

int ecall_device_init()
{
    OE_TEST(oe_enable_feature(OE_FEATURE_HOST_FILES) == OE_OK);
    OE_TEST(oe_enable_feature(OE_FEATURE_HOST_SOCKETS) == OE_OK);
    OE_TEST(oe_enable_feature(OE_FEATURE_POLLING) == OE_OK);
    OE_TEST(oe_enable_feature(OE_FEATURE_HOST_RESOLVER) == OE_OK);
    return 0;
}

int ecall_getnameinfo(char* buffer, size_t bufflen)
{
    int status = OE_FAILURE;
    (void)buffer;
    (void)bufflen;
    (void)status;

    char host[256] = {0};
    char serv[256] = {0};

    struct oe_sockaddr_in addr = {
        .sin_family = OE_AF_INET,
        .sin_port = 22,
        .sin_addr.s_addr = oe_htonl(OE_INADDR_LOOPBACK)};

    printf("s_addr=%x\n", addr.sin_addr.s_addr);

    int rslt = oe_getnameinfo(
        (const struct oe_sockaddr*)&addr,
        sizeof(addr),
        host,
        sizeof(host),
        serv,
        sizeof(serv),
        0);

    OE_TEST(rslt == 0);
    OE_TEST(strcmp(host, "") != 0);
    OE_TEST(strcmp(serv, "") != 0);

    strlcpy(buffer, host, bufflen);

    return 0;
}

extern oe_structure_t __oe_addrinfo_structure;

int ecall_getaddrinfo(struct addrinfo** buffer)
{
    struct oe_addrinfo* ai = NULL;
    struct addrinfo* ai2 = NULL;
    size_t required_size;
    oe_flat_allocator_t a;

    const char host[] = {"localhost"};
    const char service[] = {"telnet"};

    if (oe_getaddrinfo(host, service, NULL, (struct oe_addrinfo**)&ai) != 0)
    {
        OE_TEST("oe_getaddrinfo() failed" == NULL);
    }

    if (getaddrinfo(host, service, NULL, &ai2) != 0)
    {
        OE_TEST("oe_getaddrinfo() failed" == NULL);
    }

    if (addrinfo_compare((struct addrinfo*)ai, (struct addrinfo*)ai2) != 0)
    {
        OE_TEST("addrinfo_compare() failed" == NULL);
    }

    addrinfo_dump((struct addrinfo*)ai);

    /* Determine the size of the host output buffer. */
    if (oe_deep_size(&__oe_addrinfo_structure, ai, &required_size) != 0)
    {
        OE_TEST("oe_deep_size() failed" == NULL);
    }

    /* Allocate host memory and initialize the flat allocator. */
    {
        if (!(*buffer = oe_host_calloc(1, required_size)))
        {
            OE_TEST("oe_host_calloc() failed" == NULL);
        }

        oe_flat_allocator_init(&a, *buffer, required_size);
    }

    /* Copy the result from enclave to host memory. */
    if (oe_deep_copy(
            &__oe_addrinfo_structure, ai, *buffer, oe_flat_alloc, &a) != 0)
    {
        OE_TEST("oe_deep_copy() failed" == NULL);
    }

    addrinfo_dump(*buffer);

    int n = addrinfo_compare((struct addrinfo*)ai, *buffer);

    if (n != 0)
    {
        OE_TEST("addrinfo_compare() failed" == NULL);
    }

    oe_freeaddrinfo(ai);
    freeaddrinfo(ai2);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    1);   /* TCSCount */
