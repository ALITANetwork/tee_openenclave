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

int oe_hostsock_socket(int domain, int type, int protocol, int* err)
{
    int ret = socket(domain, type, protocol);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_hostsock_socketpair(
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

int oe_hostsock_connect(
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

int oe_hostsock_accept(
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

int oe_hostsock_bind(
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

int oe_hostsock_listen(int sockfd, int backlog, int* err)
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

ssize_t oe_hostsock_recvmsg(
    int sockfd,
    void* msg_name,
    socklen_t msg_namelen_in,
    socklen_t* msg_namelen_out,
    struct iovec* msg_iov,
    size_t msg_iovlen_in,
    size_t* msg_iovlen_out,
    const void* msg_control,
    size_t msg_controllen_in,
    size_t* msg_controllen_out,
    int msg_flags_in,
    int* msg_flags_out,
    int flags,
    int* err)
{
    ssize_t ret = -1;
    struct msghdr msg = {
        .msg_name = (void*)msg_name,
        .msg_namelen = msg_namelen_in,
        .msg_iov = (struct iovec*)msg_iov,
        .msg_iovlen = msg_iovlen_in,
        .msg_control = (void*)msg_control,
        .msg_controllen = msg_controllen_in,
        .msg_flags = msg_flags_in,
    };

    ret = sendmsg(sockfd, &msg, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;

        goto done;
    }

    if (msg_namelen_out)
        *msg_namelen_out = msg.msg_namelen;

    if (msg_iovlen_out)
        *msg_iovlen_out = msg.msg_iovlen;

    if (msg_controllen_out)
        *msg_controllen_out = msg.msg_controllen;

    if (msg_flags_out)
        *msg_flags_out = msg.msg_flags;

done:
    return ret;
}

ssize_t oe_hostsock_sendmsg(
    int sockfd,
    const void* msg_name,
    socklen_t msg_namelen,
    const struct iovec* msg_iov,
    size_t msg_iovlen,
    const void* msg_control,
    size_t msg_controllen,
    int msg_flags,
    int flags,
    int* err)
{
    ssize_t ret = -1;

    struct msghdr msg = {
        .msg_name = (void*)msg_name,
        .msg_namelen = msg_namelen,
        .msg_iov = (struct iovec*)msg_iov,
        .msg_iovlen = msg_iovlen,
        .msg_control = (void*)msg_control,
        .msg_controllen = msg_controllen,
        .msg_flags = msg_flags,
    };

    ret = sendmsg(sockfd, &msg, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_hostsock_recv(int sockfd, void* buf, size_t len, int flags, int* err)
{
    ssize_t ret = recv(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

ssize_t oe_hostsock_recvfrom(
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

ssize_t oe_hostsock_send(
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

ssize_t oe_hostsock_sendto(
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

int oe_hostsock_shutdown(int sockfd, int how, int* err)
{
    int ret = shutdown(sockfd, how);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_hostsock_close(int fd, int* err)
{
    int ret = close(fd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_hostsock_fcntl(int fd, int cmd, int arg, int* err)
{
    int ret = fcntl(fd, cmd, arg);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_hostsock_dup(int oldfd, int* err)
{
    int ret = dup(oldfd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_hostsock_setsockopt(
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

int oe_hostsock_getsockopt(
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

int oe_hostsock_getsockname(
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

int oe_hostsock_getpeername(
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

int oe_hostsock_shutdown_device(int sockfd, int* err)
{
    if (err)
        *err = EINVAL;

    (void)sockfd;

    /* ATTN: implement or remove. */

    return -1;
}
