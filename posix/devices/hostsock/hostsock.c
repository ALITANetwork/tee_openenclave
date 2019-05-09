// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/sockops.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/print.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>
#include "posix_t.h"

#define DEVICE_NAME "hostsock"

static size_t _get_iov_size(const struct oe_iovec* iov, size_t iov_len)
{
    size_t size = 0;

    for (size_t i = 0; i < iov_len; i++)
        size += iov[i].iov_len;

    return size;
}

static int _deflate_iov(
    const struct oe_iovec* iov,
    size_t iov_len,
    void* buf_,
    size_t buf_len)
{
    int ret = -1;
    uint8_t* buf = (uint8_t*)buf_;

    if (!iov || (buf_len && !buf))
        goto done;

    for (size_t i = 0; i < iov_len; i++)
    {
        const void* base = iov[i].iov_base;
        size_t len = iov[i].iov_len;

        if (len > buf_len)
            goto done;

        memcpy(buf, base, len);
        buf += len;
        buf_len -= len;
    }

    ret = 0;

done:
    return ret;
}

static int _inflate_iov(
    const void* buf_,
    size_t buf_len,
    struct oe_iovec* iov,
    size_t iov_len)
{
    int ret = -1;
    const uint8_t* buf = (uint8_t*)buf_;

    if (!buf || !iov)
        goto done;

    for (size_t i = 0; i < iov_len && buf_len; i++)
    {
        void* base = iov[i].iov_base;
        size_t len = iov[i].iov_len;
        size_t min = (len < buf_len) ? len : buf_len;

        memcpy(base, buf, min);
        buf += min;
        buf_len -= min;
    }

    ret = 0;

done:
    return ret;
}

#define SOCKET_MAGIC 0x536f636b

typedef struct _sock
{
    struct _oe_device base;
    uint32_t magic;
    oe_host_fd_t host_fd;
    uint64_t ready_mask;
    // epoll registers with us.
    int max_event_fds;
    int num_event_fds;
} sock_t;

static sock_t* _cast_sock(const oe_device_t* device)
{
    sock_t* sock = (sock_t*)device;

    if (sock == NULL || sock->magic != SOCKET_MAGIC)
    {
        sock = NULL;
        OE_TRACE_ERROR("sock is invalid");
        goto done;
    }
done:
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

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!(new_sock = oe_calloc(1, sizeof(sock_t))))
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
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
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
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
    oe_host_fd_t retval = -1;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    (void)_hostsock_clone(sock_, &ret);
    sock = _cast_sock(ret);

    /* Input */
    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

    if ((result = oe_posix_socket_ocall(&retval, domain, type, protocol)) !=
        OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR(
            "domain=%d type=%d protocol=%d %s",
            domain,
            type,
            protocol,
            oe_result_str(result));
        goto done;
    }

    if (retval == -1)
    {
        OE_TRACE_ERROR("retval=%d", retval);
        goto done;
    }

    sock->base.type = OE_DEVICE_TYPE_SOCKET;
    sock->base.name = DEVICE_NAME;
    sock->magic = SOCKET_MAGIC;
    sock->base.ops.sock = _hostsock.base.ops.sock;
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
    oe_host_fd_t svs[2];
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    (void)_hostsock_clone(sock_, &retdev1);
    (void)_hostsock_clone(sock_, &retdev2);
    sock1 = _cast_sock(retdev1);
    sock2 = _cast_sock(retdev2);

    /* Input */
    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

    /* Call */
    if ((result = oe_posix_socketpair_ocall(
             &ret, domain, type, protocol, svs)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR(
            "domain=%d type=%d protocol=%d result=%s",
            domain,
            type,
            protocol,
            oe_result_str(result));
        goto done;
    }

    if (ret == -1)
    {
        OE_TRACE_ERROR("ret=%d", ret);
        goto done;
    }

    {
        sock1->base.type = OE_DEVICE_TYPE_SOCKET;
        sock1->base.name = DEVICE_NAME;
        sock1->magic = SOCKET_MAGIC;
        sock1->base.ops.sock = _hostsock.base.ops.sock;
        sock1->host_fd = svs[0];

        sock2->base.type = OE_DEVICE_TYPE_SOCKET;
        sock2->base.name = DEVICE_NAME;
        sock2->magic = SOCKET_MAGIC;
        sock2->base.ops.sock = _hostsock.base.ops.sock;
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
    oe_socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || !addr || sizeof(buf) < addrlen)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    memcpy(&buf, addr, addrlen);
    _fix_address_family(&buf.addr);

    if ((result = oe_posix_connect_ocall(
             &ret, sock->host_fd, &buf.addr, addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("%s oe_errno=%d", oe_result_str(result), oe_errno);
        goto done;
    }

done:
    return ret;
}

static int _hostsock_accept(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    int ret = -1;
    oe_host_fd_t retval = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;
    oe_socklen_t addrlen_in = 0;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || (addr && !addrlen) || (addrlen && !addr))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    memset(&buf, 0, sizeof(buf));

    if (addr && addrlen)
    {
        if (sizeof(buf) < *addrlen)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR(
                "oe_errno=%d sizeof(buf)=%zu *addrlen=%u",
                oe_errno,
                sizeof(buf),
                *addrlen);
            goto done;
        }

        memcpy(&buf, addr, *addrlen);
        _fix_address_family(&buf.addr);
        addrlen_in = *addrlen;
    }

    if ((result = oe_posix_accept_ocall(
             &retval, sock->host_fd, &buf.addr, addrlen_in, addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

    if (retval == -1)
    {
        OE_TRACE_ERROR("retval=%ld", retval);
        goto done;
    }

    sock->host_fd = retval;

    ret = 0;

done:

    return ret;
}

static int _hostsock_bind(
    oe_device_t* sock_,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || !addr || sizeof(buf) < addrlen)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Input */
    memcpy(&buf, addr, addrlen);
    _fix_address_family(&buf.addr);

    if ((result = oe_posix_bind_ocall(
             &ret, sock->host_fd, &buf.addr, addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

done:

    return ret;
}

static int _hostsock_listen(oe_device_t* sock_, int backlog)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_listen_ocall(&ret, sock->host_fd, backlog)) != OE_OK)
    {
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (buf)
        memset(buf, 0, sizeof(count));

    if ((result = oe_posix_recv_ocall(
             &ret, sock->host_fd, buf, count, flags)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    oe_socklen_t* addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if ((result = oe_posix_recvfrom_ocall(
             &ret,
             sock->host_fd,
             buf,
             count,
             flags,
             (struct oe_sockaddr*)src_addr,
             addrlen_in,
             addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    void* buf = NULL;
    size_t buf_len;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Get the size the total (flat) size of the msg_iov array. */
    buf_len = _get_iov_size(msg->msg_iov, msg->msg_iovlen);

    /* Allocate the read buffer if its length is non-zero. */
    if (buf_len && !(buf = oe_calloc(1, buf_len)))
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d buf_len=%zu", oe_errno, buf_len);
        goto done;
    }

    /* Call the host. */
    {
        oe_result_t result;

        if ((result = oe_posix_recvmsg_ocall(
                 &ret,
                 sock->host_fd,
                 msg->msg_name,
                 msg->msg_namelen,
                 &msg->msg_namelen,
                 buf,
                 buf_len,
                 msg->msg_control,
                 msg->msg_controllen,
                 &msg->msg_controllen,
                 flags)) != OE_OK)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("%s", oe_result_str(result));
            goto done;
        }

        if (ret < 0)
        {
            OE_TRACE_ERROR("ret=%ld oe_errno=%d", ret, oe_errno);
            goto done;
        }
    }

    /* Copy the buffer back onto the original iov array. */
    if (_inflate_iov(buf, (size_t)ret, msg->msg_iov, msg->msg_iovlen) != 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("_inflate_iov(): oe_errno=%d", oe_errno);
        goto done;
    }

done:

    if (buf)
        oe_free(buf);

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
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_send_ocall(
             &ret, sock->host_fd, buf, count, flags)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    oe_socklen_t addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_sendto_ocall(
             &ret,
             sock->host_fd,
             buf,
             count,
             flags,
             (struct oe_sockaddr*)dest_addr,
             addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    void* buf = NULL;
    size_t buf_len;

    oe_errno = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Get the size the total (flat) size of the msg_iov array. */
    buf_len = _get_iov_size(msg->msg_iov, msg->msg_iovlen);

    /* Allocate the write buffer if its length is non-zero. */
    if (buf_len && !(buf = oe_calloc(1, buf_len)))
    {
        oe_errno = OE_ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d buf_len=%zu", oe_errno, buf_len);
        goto done;
    }

    /* Flatten the iov array onto the buffer. */
    if (_deflate_iov(msg->msg_iov, msg->msg_iovlen, buf, buf_len) != 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("_deflate_iov(): oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call the host. */
    {
        oe_result_t result;

        if ((result = oe_posix_sendmsg_ocall(
                 &ret,
                 sock->host_fd,
                 msg->msg_name,
                 msg->msg_namelen,
                 buf,
                 buf_len,
                 msg->msg_control,
                 msg->msg_controllen,
                 flags)) != OE_OK)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("ocall failed: %s", oe_result_str(result));
            goto done;
        }

        if (ret == -1)
        {
            OE_TRACE_ERROR("ret=%ld oe_errno=%d", ret, oe_errno);
            goto done;
        }
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static int _hostsock_close(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = (oe_posix_close_ocall(&ret, sock->host_fd))) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

    if (ret == 0)
        oe_free(sock);

done:

    return ret;
}

static int _hostsock_fcntl(oe_device_t* sock_, int cmd, uint64_t arg)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_fcntl_ocall(&ret, sock->host_fd, cmd, arg)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

done:

    return ret;
}

static int _hostsock_dup(oe_device_t* sock_, oe_device_t** new_sock)
{
    int ret = -1;
    oe_host_fd_t retval = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_dup_ocall(&retval, sock->host_fd)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

    if (retval != -1)
    {
        sock_t* s = NULL;

        _hostsock_clone(sock_, (oe_device_t**)&s);

        if (!s)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        s->host_fd = retval;
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
    oe_socklen_t* optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t optlen_in = 0;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (optlen)
        optlen_in = *optlen;

    if ((result = oe_posix_getsockopt_ocall(
             &ret, sock->host_fd, level, optname, optval, optlen_in, optlen)) !=
        OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    oe_socklen_t optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock || !optval || !optlen)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_setsockopt_ocall(
             &ret, sock->host_fd, level, optname, optval, optlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

done:

    return ret;
}

static int _hostsock_ioctl(
    oe_device_t* sock,
    unsigned long request,
    uint64_t arg)
{
    OE_UNUSED(sock);
    OE_UNUSED(request);
    OE_UNUSED(arg);

    oe_errno = OE_ENOTSUP;
    OE_TRACE_ERROR("oe_errno=%d ", oe_errno);

    return -1;
}

static int _hostsock_getpeername(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if ((result = oe_posix_getpeername_ocall(
             &ret,
             sock->host_fd,
             (struct oe_sockaddr*)addr,
             addrlen_in,
             addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

done:

    return ret;
}

static int _hostsock_getsockname(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (addrlen)
        addrlen_in = *addrlen;

    if ((result = oe_posix_getsockname_ocall(
             &ret,
             sock->host_fd,
             (struct oe_sockaddr*)addr,
             addrlen_in,
             addrlen)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
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
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_shutdown_ocall(&ret, sock->host_fd, how)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

    // shutdown call could be followed by a close call on a socket
    // to avoid double-free, no need  to free it here
done:

    return ret;
}

static int _hostsock_shutdown_device(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_result_t result = OE_FAILURE;

    oe_errno = 0;

    if (!sock)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((result = oe_posix_shutdown_sockets_device_ocall(
             &ret, sock->host_fd)) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("host_fd=%ld %s", sock->host_fd, oe_result_str(result));
        goto done;
    }

    if (ret != -1)
        oe_free(sock);

done:

    return ret;
}

static oe_host_fd_t _hostsock_gethostfd(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->host_fd;
}

static oe_sock_ops_t _ops = {
    .base.clone = _hostsock_clone,
    .base.release = _hostsock_release,
    .base.ioctl = _hostsock_ioctl,
    .base.fcntl = _hostsock_fcntl,
    .base.read = _hostsock_read,
    .base.write = _hostsock_write,
    .base.close = _hostsock_close,
    .base.dup = _hostsock_dup,
    .base.get_host_fd = _hostsock_gethostfd,
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
    .base.type = OE_DEVICE_TYPE_SOCKET,
    .base.name = DEVICE_NAME,
    .base.ops.sock = &_ops,
    .magic = SOCKET_MAGIC,
    .ready_mask = 0,
    .max_event_fds = 0,
    .num_event_fds = 0,
    // oe_event_device_t *event_fds;
};

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once(void)
{
    oe_result_t result = OE_FAILURE;
    const uint64_t devid = OE_DEVID_HOSTSOCK;

    if (oe_set_device(devid, &_hostsock.base) != 0)
    {
        OE_TRACE_ERROR("devid=%lu ", devid);
        goto done;
    }

    result = OE_OK;

done:

    if (result == OE_OK)
        _loaded = true;
}

oe_result_t oe_load_module_hostsock(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
