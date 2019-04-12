// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/internal/hostsock.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oe_u.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

int oe_posix_socket_ocall(int domain, int type, int protocol, int* err)
{
    int ret = socket(domain, type, protocol);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    int sv[2],
    int* err)
{
    int ret = socketpair(domain, type, protocol, sv);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_connect_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
    int ret = connect(sockfd, addr, addrlen);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_posix_accept_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    int ret = accept(sockfd, addr, &addrlen_in);

    if (ret == -1)
    {
        if (err)
            *err = errno;

        goto done;
    }

    if (addrlen_out)
        *addrlen_out = addrlen_in;

done:
    return ret;
}

int oe_posix_bind_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
    int ret = bind(sockfd, addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_listen_ocall(int sockfd, int backlog, int* err)
{
    errno = 0;

    int ret = listen(sockfd, backlog);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_posix_recvmsg_ocall(
    int sockfd,
    struct msghdr* msg,
    int flags,
    int* err)
{
    ssize_t ret = recvmsg(sockfd, msg, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;

        goto done;
    }

done:
    return ret;
}

ssize_t oe_posix_sendmsg_ocall(
    int sockfd,
    const struct msghdr* msg,
    int flags,
    int* err)
{
    ssize_t ret = sendmsg(sockfd, msg, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_posix_recv_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    int* err)
{
    ssize_t ret = recv(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_posix_recvfrom_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    ssize_t ret = recvfrom(sockfd, buf, len, flags, src_addr, &addrlen_in);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    if (addrlen_out)
        *addrlen_out = addrlen_in;

    return ret;
}

ssize_t oe_posix_send_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    int* err)
{
    ssize_t ret = send(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_posix_sendto_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* src_addr,
    socklen_t addrlen,
    int* err)
{
    ssize_t ret = sendto(sockfd, buf, len, flags, src_addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_shutdown_ocall(int sockfd, int how, int* err)
{
    int ret = shutdown(sockfd, how);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_close_ocall(int fd, int* err)
{
    int ret = close(fd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_fcntl_ocall(int fd, int cmd, int arg, int* err)
{
    int ret = fcntl(fd, cmd, arg);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_dup_ocall(int oldfd, int* err)
{
    int ret = dup(oldfd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_setsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen,
    int* err)
{
    int ret = -1;

    errno = 0;

    ret = setsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_getsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t optlen_in,
    socklen_t* optlen,
    int* err)
{
    int ret;

    if (optlen)
        *optlen = optlen_in;

    ret = getsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_getsockname_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getsockname(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_getpeername_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getpeername(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_shutdown_sockets_device_ocall(int sockfd, int* err)
{
    if (err)
        *err = EINVAL;

    (void)sockfd;

    /* ATTN: implement or remove. */

    return -1;
}
