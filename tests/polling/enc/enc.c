/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

// enclave.h must come before socket.h
#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/epoll.h>
#include <openenclave/internal/fs.h>

#include <epoll_test_t.h>
#include <stdio.h>
#include <string.h>

int ecall_device_init()
{
    (void)oe_allocate_devid(OE_DEVID_EPOLL);
    (void)oe_set_devid_device(OE_DEVID_EPOLL, oe_epoll_get_epoll());
    return 0;
}

const char* print_socket_success(int numfds, int* fdlist)
{
    static const char* msg = "socket success";
    ssize_t n;
    char buff[1024] = {0};
    (void)numfds;

    printf("%s\n", msg);
    n = oe_read(fdlist[0], buff, sizeof(buff));
    buff[n] = 0;
    printf("received data %s from fd %d\n", buff, fdlist[0]);
    return msg;
}

const char* print_file_success(int numfds, int* fdlist)
{
    static const char* msg = "file success";
    printf("%s\n", msg);
    (void)numfds;
    (void)fdlist;
    return msg;
}

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
int ecall_epoll_test(size_t buff_len, char* recv_buff)
{
    int sockfd = 0;
    int file_fd = 0;
    struct oe_sockaddr_in serv_addr = {0};
    static const int MAX_EVENTS = 20;
    struct oe_epoll_event event = {0};
    struct oe_epoll_event events[MAX_EVENTS] = {{0}};
    int epoll_fd = oe_epoll_create1(0);

    printf("--------------- epoll -------------\n");
    if (epoll_fd == -1)
    {
        printf("Failed to create epoll file descriptor\n");
        return OE_FAILURE;
    }

    memset(recv_buff, 0, buff_len);
    printf("create socket\n");
    if ((sockfd = oe_socket(OE_AF_HOST, OE_SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return OE_FAILURE;
    }
    serv_addr.sin_family = OE_AF_HOST;
    serv_addr.sin_addr.s_addr = oe_htonl(OE_INADDR_LOOPBACK);
    serv_addr.sin_port = oe_htons(1642);

    printf("socket fd = %d\n", sockfd);
    printf("Connecting...\n");
    int retries = 0;
    static const int max_retries = 4;
    while (oe_connect(
               sockfd, (struct oe_sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed \n");
            oe_close(sockfd);
            return OE_FAILURE;
        }
        else
        {
            printf("Connect Failed. Retrying \n");
        }
    }

    const int flags = OE_O_NONBLOCK | OE_O_RDONLY;
    file_fd = oe_open("/tmp/test", flags, 0);

    printf("polling...\n");
    if (file_fd >= 0)
    {
        event.events = OE_EPOLLIN;
        event.data.ptr = (void*)print_file_success;

        if (oe_epoll_ctl(epoll_fd, OE_EPOLL_CTL_ADD, 0, &event))
        {
            fprintf(stderr, "Failed to add file descriptor to epoll\n");
            oe_close(epoll_fd);
            return 1;
        }
    }

    event.events = 0x3c7;
    event.data.ptr = (void*)print_socket_success;
    if (oe_epoll_ctl(epoll_fd, OE_EPOLL_CTL_ADD, sockfd, &event))
    {
        fprintf(stderr, "Failed to add file descriptor to epoll\n");
        oe_close(epoll_fd);
        return 1;
    }

    int nfds = 0;
    do
    {
        /*while*/ if ((nfds = oe_epoll_wait(epoll_fd, events, 20, 30000)) < 0)
        {
            printf("error.\n");
        }
        else
        {
            printf("input from %d fds\n", nfds);

            for (int i = 0; i < nfds; i++)
            {
                const char* (*func)(int numfds, int* fdlist) =
                    (const char* (*)(int, int*))events[i].data.ptr;
                printf("func = %p\n", events[i].data.ptr);
                if (func)
                {
                    const char* rtn = (*func)(1, &sockfd);
                    if (rtn)
                    {
                        strncpy(recv_buff, rtn, buff_len);
                        nfds = -1; // to exit do/while
                        break;
                    }
                }
            }
        }

    } while (nfds >= 0);

    oe_close(sockfd);
    // oe_close(epoll_fd);
    oe_sleep_msec(3);

    printf("--------------- epoll done -------------\n");
    return OE_OK;
}

int ecall_select_test(size_t buff_len, char* recv_buff)
{
    int sockfd = 0;
    int file_fd = 0;
    struct oe_sockaddr_in serv_addr = {0};
    oe_fd_set readfds;
    oe_fd_set writefds;
    oe_fd_set exceptfds;
    struct oe_timeval timeout = {0};

    OE_FD_ZERO(&readfds);
    OE_FD_ZERO(&writefds);
    OE_FD_ZERO(&exceptfds);

    printf("--------------- select -------------\n");
    memset(recv_buff, 0, buff_len);
    printf("create socket\n");
    if ((sockfd = oe_socket(OE_AF_HOST, OE_SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return OE_FAILURE;
    }
    serv_addr.sin_family = OE_AF_HOST;
    serv_addr.sin_addr.s_addr = oe_htonl(OE_INADDR_LOOPBACK);
    serv_addr.sin_port = oe_htons(1642);

    printf("socket fd = %d\n", sockfd);
    printf("Connecting...\n");
    int retries = 0;
    static const int max_retries = 4;
    while (oe_connect(
               sockfd, (struct oe_sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed \n");
            oe_close(sockfd);
            return OE_FAILURE;
        }
        else
        {
            printf("Connect Failed. Retrying \n");
        }
    }
    if (sockfd >= 0)
    {
        OE_FD_SET(sockfd, &readfds);
        OE_FD_SET(sockfd, &writefds);
        OE_FD_SET(sockfd, &exceptfds);
    }

    const int flags = OE_O_NONBLOCK | OE_O_RDONLY;
    file_fd = oe_open("/tmp/test", flags, 0);

    printf("polling...\n");
    if (file_fd >= 0)
    {
        OE_FD_SET(file_fd, &readfds);
        OE_FD_SET(file_fd, &writefds);
        OE_FD_SET(file_fd, &exceptfds);
    }

    int nfds = 0;
    do
    {
        timeout.tv_sec = 30;
        if ((nfds = oe_select(1, &readfds, &writefds, &exceptfds, &timeout)) <
            0)
        {
            printf("select error.\n");
        }
        else
        {
            printf("input from %d fds\n", nfds);

            if (OE_FD_ISSET(sockfd, &readfds))
            {
                ssize_t n;
                char buff[1024] = {0};

                printf("read sockfd:%d\n", sockfd);
                n = oe_read(sockfd, buff, sizeof(buff));
                buff[n] = 0;
                if (n > 0)
                {
                    memcpy(
                        recv_buff,
                        buff,
                        ((size_t)n < buff_len) ? (size_t)n : buff_len);
                    nfds = -1;
                    break;
                }
            }
        }

    } while (nfds >= 0);

    oe_close(sockfd);
    printf("--------------- select done -------------\n");
    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    16);  /* TCSCount */
