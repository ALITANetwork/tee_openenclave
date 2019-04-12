// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/epoll.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
// clang-format on

// Poll uses much of the infrastructure from epoll.

int oe_poll(struct oe_pollfd* fds, nfds_t nfds, int timeout_ms)
{
    oe_device_t* pepoll = NULL;
    int retval = -1;
    int epfd = -1;
    nfds_t i = 0;
    struct oe_epoll_event* rev =
        oe_malloc(sizeof(struct oe_epoll_event) * nfds);
    bool has_host_wait;

    epfd = oe_epoll_create1(0);
    if (epfd < 0)
    {
        return epfd;
    }

    pepoll = oe_get_fd_device(epfd);
    if (!pepoll)
    {
        goto done;
    }

    if (pepoll->ops.epoll->addeventdata == NULL)
    {
        oe_errno = EINVAL;
        retval = -1;
        goto done;
    }

    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
        {
            struct oe_epoll_event ev = {.data.fd = fds[i].fd,
                                        .events = (uint32_t)fds[i].events};

            retval = (*pepoll->ops.epoll->addeventdata)(
                epfd, fds[i].fd, ev.events, ev.data.u64);
            if (retval < 0)
            {
                goto done;
            }
        }
    }

    has_host_wait = true; // false;
    // 2do. We need to figure out how to wait

    if (!pepoll)
    {
        // Log error here
        retval = -1; // errno is already set
        goto done;
    }

    if (pepoll->ops.epoll->poll == NULL)
    {
        oe_errno = EINVAL;
        retval = -1;
        goto done;
    }

    // Start an outboard waiter if host involved
    // search polled device list for host involved  2Do
    if (has_host_wait)
    {
        if ((retval = (*pepoll->ops.epoll->poll)(
                 epfd, fds, (size_t)nfds, timeout_ms)) < 0)
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    // We check immedately because we might have gotten lucky and had stuff come
    // in immediately. If so we skip the wait
    retval = oe_get_epoll_events((uint64_t)epfd, (size_t)nfds, rev);

    if (retval == 0)
    {
        if (oe_wait_device_notification(timeout_ms) < 0)
        {
            oe_errno = EPROTO;
            goto done;
        }
        retval = oe_get_epoll_events((uint64_t)epfd, (size_t)nfds, rev);
    }

    if (retval < 0)
    {
        goto done;
    }

    /* output */
    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd == -1)
        {
            fds[i].revents = POLLNVAL;
            continue;
        }

        int j = 0;
        for (j = 0; j < retval; j++)
        {
            if (rev[j].data.fd < 0)
            {
                continue;
            }
            if (fds[i].fd == rev[j].data.fd)
            {
                fds[i].revents = (int16_t)rev[j].events;
                rev[j].data.fd = -1; /* done with this ev desc */
                break;
            }
        }
    }

done:
    oe_free(rev);
    return retval;
}
