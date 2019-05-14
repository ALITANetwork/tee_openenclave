// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/corelibc/time.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/trace.h>

void _set_to_fd_list(
    oe_fd_set* set,
    int flags,
    int fdlist_max,
    int* fd_list,
    int* fd_flags)
{
    int fd_idx = 0;
    uint32_t idx = 0;
    uint32_t* pbits = (uint32_t*)set->fds_bits;
    uint32_t bitpos;

    for (idx = 0; idx<OE_FD_SETSIZE>> 5; idx++)
    {
        uint32_t bitmask = 1;
        for (bitpos = 0; bitpos < 8 * sizeof(long); bitpos++)
        {
            if (pbits[idx] & bitmask)
            {
                uint32_t fd = (idx << 5) + bitpos;
                if (fd_idx < fdlist_max)
                {
                    for (fd_idx = 0; fd_idx < fdlist_max; fd_idx++)
                    {
                        if ((fd_list[fd_idx] == (int)fd) ||
                            (fd_list[fd_idx] == (int)0xffffffff))
                        {
                            // If the fd is in the list, break
                            // if the fdlist is empty here, break
                            break;
                        }
                    }

                    if (fd_list[fd_idx] == (int)0xffffffff)
                    {
                        fd_list[fd_idx] = (int)fd;
                    }

                    fd_flags[fd] |= flags;
                }
            }
            bitmask <<= 1;
        }
    }
}

void _ev_list_to_set(
    int nev,
    struct oe_epoll_event* pevent,
    uint32_t mask,
    oe_fd_set* set)
{
    int i = 0;

    for (i = 0; i < nev; i++)
    {
        if ((pevent[i].events & mask) != 0)
        {
            OE_FD_SET(pevent[i].data.fd, set);
        }
    }
}

int oe_select(
    int nfds,
    oe_fd_set* readfds,
    oe_fd_set* writefds,
    oe_fd_set* exceptfds,
    struct oe_timeval* timeout)
{
    int fd_list[OE_FD_SETSIZE] = {0};  // <nfds> members
    int fd_flags[OE_FD_SETSIZE] = {0}; // indexed by fd
    int i = 0;
    int epfd = -1;
    int ret = -1;
    int ret_fds = -1;
    struct oe_epoll_event rtn_ev[OE_FD_SETSIZE] = {{0}};
    int timeout_ms = -1;

    if (timeout)
    {
        timeout_ms = (int)timeout->tv_sec * 1000;
        timeout_ms += (int)(timeout->tv_usec / 1000);
    }

    {
        const size_t num_bytes = sizeof(uint32_t) * (size_t)(nfds + 1);

        if (oe_memset_s(fd_list, num_bytes, 0xff, num_bytes) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (readfds)
    {
        _set_to_fd_list(
            readfds,
            (OE_EPOLLIN | OE_EPOLLRDNORM | OE_EPOLLRDBAND),
            nfds,
            fd_list,
            fd_flags);
    }

    if (writefds)
    {
        _set_to_fd_list(
            writefds,
            (OE_EPOLLOUT | OE_EPOLLWRNORM | OE_EPOLLWRBAND),
            nfds,
            fd_list,
            fd_flags);
    }

    if (exceptfds)
    {
        _set_to_fd_list(
            exceptfds,
            (OE_EPOLLERR | OE_EPOLLHUP | OE_EPOLLRDHUP | OE_EPOLLWAKEUP),
            nfds,
            fd_list,
            fd_flags);
    }

    epfd = oe_epoll_create1(0);
    if (epfd < 0)
        OE_RAISE_ERRNO(oe_errno);

    for (i = 0; i < nfds; i++)
    {
        struct oe_epoll_event ev = {
            .data.fd = fd_list[i],
            .events = (uint32_t)fd_flags[fd_list[i]],
        };

        ret = oe_epoll_ctl(epfd, OE_EPOLL_CTL_ADD, fd_list[i], &ev);
        if (ret < 0)
        {
            OE_RAISE_ERRNO_MSG(
                OE_EINVAL, "epfd=%d fd_list[%d]=%d", epfd, i, fd_list[i]);
        }
    }

    ret_fds = oe_epoll_wait(epfd, rtn_ev, OE_FD_SETSIZE, timeout_ms);
    if (ret_fds < 0)
    {
        goto done;
    }

    if (readfds)
        OE_FD_ZERO(readfds);

    if (writefds)
        OE_FD_ZERO(writefds);

    if (exceptfds)
        OE_FD_ZERO(exceptfds);

    if (readfds)
    {
        _ev_list_to_set(
            ret_fds,
            rtn_ev,
            (OE_EPOLLIN | OE_EPOLLRDNORM | OE_EPOLLRDBAND),
            readfds);
    }

    if (writefds)
    {
        _ev_list_to_set(
            ret_fds,
            rtn_ev,
            (OE_EPOLLOUT | OE_EPOLLWRNORM | OE_EPOLLWRBAND),
            writefds);
    }

    if (exceptfds)
    {
        _ev_list_to_set(
            ret_fds,
            rtn_ev,
            (OE_EPOLLERR | OE_EPOLLHUP | OE_EPOLLRDHUP | OE_EPOLLWAKEUP),
            exceptfds);
    }
done:

    if (epfd >= 0)
        oe_close(epfd);

    return ret_fds;
}

void OE_FD_CLR(int fd, oe_fd_set* set)
{
    int l = fd >> 5;   // long index
    int b = fd & 0x1f; // bit shift
    set->fds_bits[l] &= ~(1UL << b);
}

int OE_FD_ISSET(int fd, oe_fd_set* set)
{
    int l = fd >> 5;   // long index
    int b = fd & 0x1f; // bit shift
    return (set->fds_bits[l] & (1UL << b)) != 0;
}

void OE_FD_SET(int fd, oe_fd_set* set)
{
    int l = fd >> 5;   // long index
    int b = fd & 0x1f; // bit shift

    set->fds_bits[l] |= (1UL << b);
}

void OE_FD_ZERO(oe_fd_set* set)
{
    int i = 0;
    uint64_t* bits = set->fds_bits;

    while ((uint32_t)i < (sizeof(oe_fd_set) / sizeof(uint64_t)))
    {
        bits[i++] = 0;
    }
}
