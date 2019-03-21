// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#include <netinet/in.h>
#include <openenclave/internal/tests.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "resolver_test_u.h"

#define SERVER_PORT "12345"

void oe_resolver_install_hostresolver();

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* client_enclave = NULL;
    int ret = 0;
    const uint32_t flags = oe_get_create_flags();

    char host[256];

    struct addrinfo* paddrinfo = NULL;
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    oe_resolver_install_hostresolver();
    result = oe_create_resolver_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_device_init(client_enclave, &ret) == OE_OK);

    OE_TEST(ecall_getaddrinfo(client_enclave, &ret, &paddrinfo) == OE_OK);

    if (!paddrinfo)
    {
        printf("host received: paddrinfo == NULL\n");
    }
    else
    {
        uint8_t* addr =
            (uint8_t*)&((struct sockaddr_in*)paddrinfo->ai_addr)->sin_addr;
        OE_TEST(
            addr[0] == 0x7f && addr[1] == 0 && addr[2] == 0 && addr[3] == 1);
        printf(
            "host received: paddrinfo->ai_addr: %02x %02x %02x %02x\n",
            addr[0],
            addr[1],
            addr[2],
            addr[3]);
    }

    OE_TEST(
        ecall_getnameinfo(client_enclave, &ret, host, sizeof(host)) == OE_OK);

    {
        OE_TEST(strcmp(host, "localhost") == 0);
        printf("host received: host = %s\n", host);
    }

    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);

    printf("=== passed all tests (resolver_test)\n");

    return 0;
}
