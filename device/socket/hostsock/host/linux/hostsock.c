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
#include "../../../../../common/oe_u.h"
#include "../../common/hostsockargs.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

void oe_handle_hostsock_ocall(void* args_)
{
    oe_hostsock_args_t* args = (oe_hostsock_args_t*)args_;
    socklen_t* addrlen = NULL;
    struct sockaddr* paddr = NULL;

    /* ATTN: handle errno propagation. */

    if (!args)
        return;

    args->err = 0;
    switch (args->op)
    {
        case OE_HOSTSOCK_OP_NONE:
        {
            break;
        }
#if 0
        case OE_HOSTSOCK_OP_SOCKET:
        {
            args->u.socket.ret = socket(
                args->u.socket.domain,
                args->u.socket.type,
                args->u.socket.protocol);
            break;
        }
#endif
        case OE_HOSTSOCK_OP_CLOSE:
        {
            args->u.close.ret = close((int)args->u.close.host_fd);
            break;
        }
        case OE_HOSTSOCK_OP_DUP:
        {
            args->u.dup.ret = dup((int)args->u.dup.host_fd);
            break;
        }
        case OE_HOSTSOCK_OP_RECV:
        {
            args->u.recv.ret = recv(
                (int)args->u.recv.host_fd,
                args->buf,
                args->u.recv.count,
                args->u.recv.flags);
            break;
        }
        case OE_HOSTSOCK_OP_RECVFROM:
        {
            args->u.recvfrom.ret = recvfrom(
                (int)args->u.recvfrom.host_fd,
                args->buf,
                args->u.recvfrom.count,
                args->u.recvfrom.flags,
                (struct sockaddr*)(args->buf + args->u.recvfrom.count),
                &args->u.recvfrom.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_RECVMSG:
        {
            args->u.recvmsg.ret = recvmsg(
                (int)args->u.recvmsg.host_fd,
                (struct msghdr*)args->buf,
                args->u.recvmsg.flags);
            break;
        }
        case OE_HOSTSOCK_OP_SEND:
        {
            args->u.send.ret = send(
                (int)args->u.send.host_fd,
                args->buf,
                args->u.send.count,
                args->u.send.flags);
            break;
        }
        case OE_HOSTSOCK_OP_SENDTO:
        {
            args->u.sendto.ret = sendto(
                (int)args->u.sendto.host_fd,
                args->buf,
                args->u.sendto.count,
                args->u.sendto.flags,
                (const struct sockaddr*)(args->buf + args->u.sendto.count),
                args->u.sendto.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_SENDMSG:
        {
            args->u.sendmsg.ret = sendmsg(
                (int)args->u.sendmsg.host_fd,
                (const struct msghdr*)args->buf,
                args->u.sendmsg.flags);
            break;
        }
        case OE_HOSTSOCK_OP_CONNECT:
        {
            args->u.connect.ret = connect(
                (int)args->u.connect.host_fd,
                (const struct sockaddr*)args->buf,
                args->u.connect.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_ACCEPT:
        {
            if (args->u.accept.addrlen != (socklen_t)-1)
            {
                addrlen = &args->u.accept.addrlen;
                paddr = (struct sockaddr*)args->buf;
            }
            args->u.accept.ret = accept(
                (int)args->u.accept.host_fd, (struct sockaddr*)paddr, addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_BIND:
        {
            args->u.bind.ret = bind(
                (int)args->u.bind.host_fd,
                (const struct sockaddr*)args->buf,
                args->u.bind.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_LISTEN:
        {
            args->u.listen.ret =
                listen((int)args->u.listen.host_fd, args->u.listen.backlog);
            break;
        }
        case OE_HOSTSOCK_OP_SOCK_SHUTDOWN:
        {
            args->u.sock_shutdown.ret = shutdown(
                (int)args->u.sock_shutdown.host_fd, args->u.sock_shutdown.how);
            break;
        }
        case OE_HOSTSOCK_OP_GETSOCKOPT:
        {
            args->u.getsockopt.ret = getsockopt(
                (int)args->u.getsockopt.host_fd,
                args->u.getsockopt.level,
                args->u.getsockopt.optname,
                args->buf,
                &args->u.getsockopt.optlen);
            break;
        }
        case OE_HOSTSOCK_OP_SETSOCKOPT:
        {
            args->u.setsockopt.ret = getsockopt(
                (int)args->u.setsockopt.host_fd,
                args->u.setsockopt.level,
                args->u.setsockopt.optname,
                args->buf,
                &args->u.setsockopt.optlen);
            break;
        }
        case OE_HOSTSOCK_OP_GETPEERNAME:
        {
            args->u.getpeername.ret = getpeername(
                (int)args->u.getpeername.host_fd,
                (struct sockaddr*)args->buf,
                &args->u.getpeername.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_GETSOCKNAME:
        {
            args->u.getsockname.ret = getsockname(
                (int)args->u.getsockname.host_fd,
                (struct sockaddr*)args->buf,
                &args->u.getsockname.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_SHUTDOWN_DEVICE:
        {
            // 2do
            break;
        }
        default:
        {
            // Invalid
            break;
        }
    }
    args->err = errno;
}

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
    socklen_t* addrlen,
    int* err)
{
    /* ATTN */ return 0;
}

int oe_hostsock_getpeername(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int* err)
{
    /* ATTN */ return 0;
}
