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
#include "../common/hostsockargs.h"
#include "../../../common/oe_t.h"

/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

static oe_host_batch_t* _host_batch;
static oe_spinlock_t _lock;

static void _atexit_handler()
{
    oe_spin_lock(&_lock);
    oe_host_batch_delete(_host_batch);
    _host_batch = NULL;
    oe_spin_unlock(&_lock);
}

static oe_host_batch_t* _get_host_batch(void)
{
    const size_t BATCH_SIZE = sizeof(oe_hostsock_args_t) + OE_BUFSIZ;

    if (_host_batch == NULL)
    {
        oe_spin_lock(&_lock);

        if (_host_batch == NULL)
        {
            _host_batch = oe_host_batch_new(BATCH_SIZE);
            oe_atexit(_atexit_handler);
        }

        oe_spin_unlock(&_lock);
    }

    return _host_batch;
}

static ssize_t _copy_iov(
    struct oe_msghdr* dst,
    const struct oe_msghdr* src,
    ssize_t bytes_available)

{
    ssize_t required = -1;
    size_t iovidx = 0;
    uint8_t* pbuf = (uint8_t*)dst;

    pbuf += src->msg_namelen;
    pbuf += sizeof(struct oe_iovec) * src->msg_iovlen;
    for (iovidx = 0; iovidx < src->msg_iovlen; iovidx++)
    {
        pbuf += src->msg_iov[iovidx].iov_len;
    }
    pbuf += src->msg_controllen;

    required = (pbuf - (uint8_t*)dst);
    if (!dst)
    {
        return (ssize_t)required;
    }

    if ((ssize_t)required > bytes_available)
    {
        return -1;
    }

    pbuf = (uint8_t*)dst;
    dst->msg_namelen = src->msg_namelen;
    dst->msg_name = pbuf;
    memcpy(dst->msg_name, src->msg_name, src->msg_namelen);
    pbuf += src->msg_namelen;

    dst->msg_iovlen = src->msg_iovlen;
    pbuf += sizeof(struct oe_iovec) * src->msg_iovlen;

    for (iovidx = 0; iovidx < src->msg_iovlen; iovidx++)
    {
        dst->msg_iov[iovidx].iov_base = pbuf;
        dst->msg_iov[iovidx].iov_len = src->msg_iov[iovidx].iov_len;
        memcpy(
            dst->msg_iov[iovidx].iov_base,
            src->msg_iov[iovidx].iov_base,
            src->msg_iov[iovidx].iov_len);
        pbuf += src->msg_iov[iovidx].iov_len;
    }

    dst->msg_controllen = src->msg_controllen;
    dst->msg_control = pbuf;
    memcpy(dst->msg_control, src->msg_control, src->msg_controllen);
    pbuf += dst->msg_controllen;

    dst->msg_flags = src->msg_flags;

    return required;
}

/*
**==============================================================================
**
** hostsock operations:
**
**==============================================================================
*/

#define SOCKET_MAGIC 0x536f636b

typedef oe_hostsock_args_t args_t;

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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    ssize_t required = _copy_iov(NULL, msg, 0);
    {
        if (!(args = oe_host_batch_calloc(
                  batch, sizeof(args_t) + (size_t)required)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        // the args->buf has [ msg_hdr | iovs | [*iov_base[0] | .. |
        // [*iov_base[n]] | msg_control ]
        //

        args->op = OE_HOSTSOCK_OP_RECVMSG;
        args->u.recvmsg.ret = -1;
        args->u.recvmsg.host_fd = sock->host_fd;
        args->u.recvmsg.flags = flags;

        (void)_copy_iov((struct oe_msghdr*)args->buf, msg, required);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.recv.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        if (_copy_iov(msg, (const struct oe_msghdr*)args->buf, required) < 0)
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

done:
    if (args)
        oe_host_batch_free(batch);

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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + count)))
        {
            oe_errno = ENOMEM;
            goto done;
        }
        args->op = OE_HOSTSOCK_OP_SENDTO;
        args->u.sendto.ret = -1;
        args->u.sendto.host_fd = sock->host_fd;
        args->u.sendto.count = count;
        args->u.sendto.flags = flags;
        args->u.sendto.addrlen = addrlen;
        memcpy(args->buf, buf, count);
        memcpy(args->buf + count, dest_addr, addrlen);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.sendto.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static ssize_t _hostsock_sendmsg(
    oe_device_t* sock_,
    const struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        ssize_t required = _copy_iov(NULL, msg, 0);
        if (!(args = oe_host_batch_calloc(
                  batch, sizeof(args_t) + (size_t)required)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SEND;
        args->u.sendmsg.ret = -1;
        args->u.send.host_fd = sock->host_fd;
        args->u.send.flags = flags;
        (void)_copy_iov((struct oe_msghdr*)args->buf, msg, required);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.send.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    if (args)
        oe_host_batch_free(batch);
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
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !optval || !optlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *optlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_GETSOCKOPT;
        args->u.getsockopt.ret = -1;
        args->u.getsockopt.host_fd = sock->host_fd;
        args->u.getsockopt.level = level;
        args->u.getsockopt.optname = optname;
        args->u.getsockopt.optlen = *optlen;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getsockopt.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *optlen = args->u.getsockopt.optlen;
        memcpy(optval, args->buf, *optlen);
    }

done:
    if (args)
        oe_host_batch_free(batch);

    return (int)ret;
}

static int _hostsock_setsockopt(
    oe_device_t* sock_,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !optval || !optlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + optlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SETSOCKOPT;
        args->u.setsockopt.ret = -1;
        args->u.setsockopt.host_fd = sock->host_fd;
        args->u.setsockopt.level = level;
        args->u.setsockopt.optname = optname;
        args->u.setsockopt.optlen = optlen;
        memcpy(args->buf, optval, optlen);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.setsockopt.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    if (args)
        oe_host_batch_free(batch);

    return (int)ret;
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
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr || !addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_GETPEERNAME;
        args->u.getpeername.ret = -1;
        args->u.getpeername.host_fd = sock->host_fd;
        args->u.getpeername.addrlen = *addrlen;
        memcpy(args->buf, addr, *addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getpeername.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *addrlen = args->u.getpeername.addrlen;
        memcpy(addr, args->buf, *addrlen);
    }

done:
    if (args)
        oe_host_batch_free(batch);

    return (int)ret;
}

static int _hostsock_getsockname(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr || !addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_GETSOCKNAME;
        args->u.getsockname.ret = -1;
        args->u.getsockname.host_fd = sock->host_fd;
        args->u.getsockname.addrlen = *addrlen;
        memcpy(args->buf, addr, *addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getsockname.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *addrlen = args->u.getsockname.addrlen;
        memcpy(addr, args->buf, *addrlen);
    }

done:
    if (args)
        oe_host_batch_free(batch);

    return (int)ret;
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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SHUTDOWN_DEVICE;
        args->u.shutdown_device.ret = -1;
        args->u.shutdown_device.host_fd = sock->host_fd;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.shutdown_device.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Release the sock_ object. */
    oe_free(sock);

    ret = 0;

done:
    if (args)
        oe_host_batch_free(batch);

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
