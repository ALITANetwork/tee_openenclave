// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/internal/sock_ops.h>
#include <openenclave/internal/hostsock.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/hostbatch.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/print.h>
#include "oe_t.h"

/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

static oe_host_batch_t* _host_batch;
static oe_spinlock_t _lock;

/*
**==============================================================================
**
** hostsock operations:
**
**==============================================================================
*/

#define SOCKET_MAGIC 0x536f636b

typedef struct _sock
{
    struct _oe_device base;
    uint32_t magic;
    int64_t host_fd;
    uint64_t ready_mask;
    // epoll registers with us.
    int max_event_fds;
    int num_event_fds;
    // oe_event_device_t *event_fds;
} sock_t;

static sock_t* _cast_sock(const oe_device_t* device)
{
    sock_t* sock = (sock_t*)device;

    if (sock == NULL || sock->magic != SOCKET_MAGIC)
        return NULL;

    return sock;
}

static sock_t _hostsock;
static ssize_t _hostsock_read(oe_device_t*, void* buf, size_t count);

static int _hostsock_close(oe_device_t*);

static int _hostsock_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    sock_t* sock = _cast_sock(device);
    sock_t* new_sock = NULL;

    if (!sock || !new_device)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!(new_sock = oe_calloc(1, sizeof(sock_t))))
    {
        oe_errno = ENOMEM;
        goto done;
    }

    memcpy(new_sock, sock, sizeof(sock_t));

    *new_device = &new_sock->base;
    ret = 0;

done:
    return ret;
}

static int _hostsock_release(oe_device_t* device)
{
    int ret = -1;
    sock_t* sock = _cast_sock(device);

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    oe_free(sock);
    ret = 0;

done:
    return ret;
}

static oe_device_t* _hostsock_socket(
    oe_device_t* sock_,
    int domain,
    int type,
    int protocol)
{
    oe_device_t* ret = NULL;
    sock_t* sock = NULL;
    int retval = -1;

    oe_errno = 0;

    (void)_hostsock_clone(sock_, &ret);
    sock = _cast_sock(ret);

    /* Input */
    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

    if (oe_hostsock_socket(&retval, domain, type, protocol, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (retval == -1)
        goto done;

    sock->base.type = OE_DEVICETYPE_SOCKET;
    sock->base.size = sizeof(sock_t);
    sock->magic = SOCKET_MAGIC;
    sock->base.ops.socket = _hostsock.base.ops.socket;
    sock->host_fd = retval;
    sock = NULL;

done:

    if (sock)
        oe_free(sock);

    return ret;
}

static ssize_t _hostsock_socketpair(
    oe_device_t* sock_,
    int domain,
    int type,
    int protocol,
    oe_device_t* retdevs[2])
{
    int ret = -1;
    oe_device_t* retdev1 = NULL;
    oe_device_t* retdev2 = NULL;
    sock_t* sock1 = NULL;
    sock_t* sock2 = NULL;
    int svs[2];

    oe_errno = 0;

    (void)_hostsock_clone(sock_, &retdev1);
    (void)_hostsock_clone(sock_, &retdev2);
    sock1 = _cast_sock(retdev1);
    sock2 = _cast_sock(retdev2);

    /* Input */
    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

    /* Call */
    if (oe_hostsock_socketpair(&ret, domain, type, protocol, svs, &oe_errno) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (ret == -1)
        goto done;

    {
        sock1->base.type = OE_DEVICETYPE_SOCKET;
        sock1->base.size = sizeof(sock_t);
        sock1->magic = SOCKET_MAGIC;
        sock1->base.ops.socket = _hostsock.base.ops.socket;
        sock1->host_fd = svs[0];

        sock2->base.type = OE_DEVICETYPE_SOCKET;
        sock2->base.size = sizeof(sock_t);
        sock2->magic = SOCKET_MAGIC;
        sock2->base.ops.socket = _hostsock.base.ops.socket;
        sock2->host_fd = svs[1];
        retdevs[0] = retdev1;
        retdevs[1] = retdev2;
    }

    sock1 = NULL;

done:

    if (sock1)
        oe_free(sock1);

    if (sock2)
        oe_free(sock2);

    return ret;
}

static void _fix_address_family(struct oe_sockaddr* addr)
{
    if (addr->sa_family == OE_AF_HOST)
        addr->sa_family = OE_AF_INET;
}

typedef struct
{
    struct oe_sockaddr addr;
    uint8_t extra[1024];
} sockaddr_t;

static int _hostsock_connect(
    oe_device_t* sock_,
    const struct oe_sockaddr* addr,
    socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !addr || sizeof(buf) < addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    memcpy(&buf, addr, addrlen);
    _fix_address_family(&buf.addr);

    if (oe_hostsock_connect(
            &ret,
            (int)sock->host_fd,
            (struct sockaddr*)&buf.addr,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:
    return ret;
}

static int _hostsock_accept(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;
    socklen_t addrlen_in = 0;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || (addr && !addrlen) || (addrlen && !addr))
    {
        oe_errno = EINVAL;
        goto done;
    }

    memset(&buf, 0, sizeof(buf));

    if (addr && addrlen)
    {
        if (sizeof(buf) < *addrlen)
        {
            oe_errno = EINVAL;
            goto done;
        }

        memcpy(&buf, addr, *addrlen);
        _fix_address_family(&buf.addr);
        addrlen_in = *addrlen;
    }

    if (oe_hostsock_accept(
            &ret,
            (int)sock->host_fd,
            (struct sockaddr*)&buf.addr,
            addrlen_in,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (ret == -1)
        goto done;

    /* ATTN: is this right (overwritting the original host_fd? */
    sock->host_fd = ret;

done:
    return ret;
}

static int _hostsock_bind(
    oe_device_t* sock_,
    const struct oe_sockaddr* addr,
    socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !addr || sizeof(buf) < addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    memcpy(&buf, addr, addrlen);
    _fix_address_family(&buf.addr);

    if (oe_hostsock_bind(
            &ret,
            (int)sock->host_fd,
            (struct sockaddr*)&buf.addr,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static int _hostsock_listen(oe_device_t* sock_, int backlog)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_listen(&ret, (int)sock->host_fd, backlog, &oe_errno) !=
        OE_OK)
    {
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_recv(
    oe_device_t* sock_,
    void* buf,
    size_t count,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (buf)
        memset(buf, 0, sizeof(count));

    if (oe_hostsock_recv(
            &ret, (int)sock->host_fd, buf, count, flags, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_recvfrom(
    oe_device_t* sock_,
    void* buf,
    size_t count,
    int flags,
    const struct oe_sockaddr* src_addr,
    socklen_t* addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_hostsock_recvfrom(
            &ret,
            (int)sock->host_fd,
            buf,
            count,
            flags,
            (struct sockaddr*)src_addr,
            addrlen_in,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_recvmsg(
    oe_device_t* sock_,
    struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_recvmsg(
            &ret,
            (int)sock->host_fd,
            msg->msg_name,
            msg->msg_namelen,
            &msg->msg_namelen,
            (struct iovec*)msg->msg_iov,
            msg->msg_iovlen,
            &msg->msg_iovlen,
            msg->msg_control,
            msg->msg_controllen,
            &msg->msg_controllen,
            msg->msg_flags,
            &msg->msg_flags,
            flags,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_send(
    oe_device_t* sock_,
    const void* buf,
    size_t count,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_send(
            &ret, (int)sock->host_fd, buf, count, flags, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_sendto(
    oe_device_t* sock_,
    const void* buf,
    size_t count,
    int flags,
    const struct oe_sockaddr* dest_addr,
    socklen_t addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_sendto(
            &ret,
            (int)sock->host_fd,
            buf,
            count,
            flags,
            (struct sockaddr*)dest_addr,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_sendmsg(
    oe_device_t* sock_,
    const struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_sendmsg(
            &ret,
            (int)sock->host_fd,
            msg->msg_name,
            msg->msg_namelen,
            (struct iovec*)msg->msg_iov,
            msg->msg_iovlen,
            msg->msg_control,
            msg->msg_controllen,
            msg->msg_flags,
            flags,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static int _hostsock_close(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_close(&ret, (int)sock->host_fd, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (ret == 0)
        oe_free(sock);

done:

    return ret;
}

static int _hostsock_dup(oe_device_t* sock_, oe_device_t** new_sock)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_dup(&ret, (int)sock->host_fd, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (ret != -1)
    {
        sock_t* s = NULL;

        _hostsock_clone(sock_, (oe_device_t**)&s);

        if (!s)
        {
            oe_errno = EINVAL;
            goto done;
        }

        s->host_fd = ret;
        *new_sock = (oe_device_t*)s;
    }

    ret = 0;

done:

    return ret;
}

static int _hostsock_getsockopt(
    oe_device_t* sock_,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    socklen_t optlen_in = 0;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (optlen)
        optlen_in = *optlen;

    if (oe_hostsock_getsockopt(
            &ret,
            (int)sock->host_fd,
            level,
            optname,
            optval,
            optlen_in,
            optlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static int _hostsock_setsockopt(
    oe_device_t* sock_,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !optval || !optlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_setsockopt(
            &ret,
            (int)sock->host_fd,
            level,
            optname,
            optval,
            optlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static int _hostsock_ioctl(
    oe_device_t* sock_,
    unsigned long request,
    oe_va_list ap)
{
    /* Unsupported */
    oe_errno = ENOTTY;
    (void)sock_;
    (void)request;
    (void)ap;
    return -1;
}

static int _hostsock_getpeername(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_hostsock_getpeername(
            &ret,
            (int)sock->host_fd,
            (struct sockaddr*)addr,
            addrlen_in,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static int _hostsock_getsockname(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_hostsock_getsockname(
            &ret,
            (int)sock->host_fd,
            (struct sockaddr*)addr,
            addrlen_in,
            addrlen,
            &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:

    return ret;
}

static ssize_t _hostsock_read(oe_device_t* sock_, void* buf, size_t count)
{
    return _hostsock_recv(sock_, buf, count, 0);
}

static ssize_t _hostsock_write(
    oe_device_t* sock_,
    const void* buf,
    size_t count)
{
    return _hostsock_send(sock_, buf, count, 0);
}

static int _hostsock_socket_shutdown(oe_device_t* sock_, int how)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_shutdown(&ret, (int)sock->host_fd, how, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* ATTN: Release the sock_ object. */

done:

    return ret;
}

static int _hostsock_shutdown_device(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock_)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostsock_shutdown_device(&ret, (int)sock->host_fd, &oe_errno) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (ret != -1)
        oe_free(sock);

done:

    return ret;
}

static int _hostsock_notify(oe_device_t* sock_, uint64_t notification_mask)
{
    sock_t* sock = _cast_sock(sock_);

    if (sock->ready_mask != notification_mask)
    {
        // We notify any epolls in progress.
    }
    sock->ready_mask = notification_mask;
    return 0;
}

static ssize_t _hostsock_gethostfd(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->host_fd;
}

static uint64_t _hostsock_readystate(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->ready_mask;
}

static oe_sock_ops_t _ops = {
    .base.clone = _hostsock_clone,
    .base.release = _hostsock_release,
    .base.ioctl = _hostsock_ioctl,
    .base.read = _hostsock_read,
    .base.write = _hostsock_write,
    .base.close = _hostsock_close,
    .base.dup = _hostsock_dup,
    .base.notify = _hostsock_notify,
    .base.get_host_fd = _hostsock_gethostfd,
    .base.ready_state = _hostsock_readystate,
    .base.shutdown = _hostsock_shutdown_device,
    .socket = _hostsock_socket,
    .socketpair = _hostsock_socketpair,
    .connect = _hostsock_connect,
    .accept = _hostsock_accept,
    .bind = _hostsock_bind,
    .listen = _hostsock_listen,
    .shutdown = _hostsock_socket_shutdown,
    .getsockopt = _hostsock_getsockopt,
    .setsockopt = _hostsock_setsockopt,
    .getpeername = _hostsock_getpeername,
    .getsockname = _hostsock_getsockname,
    .recv = _hostsock_recv,
    .send = _hostsock_send,
    .recvfrom = _hostsock_recvfrom,
    .sendto = _hostsock_sendto,
    .recvmsg = _hostsock_recvmsg,
    .sendmsg = _hostsock_sendmsg,
};

static sock_t _hostsock = {
    .base.type = OE_DEVICETYPE_SOCKET,
    .base.size = sizeof(sock_t),
    .base.ops.socket = &_ops,
    .magic = SOCKET_MAGIC,
    .ready_mask = 0,
    .max_event_fds = 0,
    .num_event_fds = 0,
    // oe_event_device_t *event_fds;
};

oe_device_t* oe_get_hostsock_device(void)
{
    return &_hostsock.base;
}

int oe_register_hostsock_device(void)
{
    int ret = -1;
    const uint64_t devid = OE_DEVID_HOST_SOCKET;

    /* Allocate the device id. */
    if (oe_allocate_devid(devid) != devid)
        goto done;

    /* Add the hostfs device to the device table. */
    if (oe_set_devid_device(devid, oe_get_hostsock_device()) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}
