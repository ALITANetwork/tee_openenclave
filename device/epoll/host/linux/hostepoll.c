// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/epoll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../../../common/oe_u.h"

typedef struct _wait_args
{
    int64_t enclaveid;
    int epfd;
    int maxevents;
    struct epoll_event events[];
} wait_args_t;

static void* epoll_wait_thread(void* arg_)
{
    int ret = 0;
    wait_args_t* args = (wait_args_t*)arg_;
    int retval;

    ret = epoll_wait(args->epfd, args->events, args->maxevents, -1);

    if (ret >= 0)
    {
        size_t num_notifications = (size_t)ret;
        struct epoll_event* ev = args->events;
        struct oe_device_notifications* notifications =
            (struct oe_device_notifications*)ev;

        OE_STATIC_ASSERT(sizeof(notifications[0]) == sizeof(ev[0]));

        if (oe_polling_notify(
                (oe_enclave_t*)args->enclaveid,
                &retval,
                notifications,
                num_notifications) != OE_OK)
        {
            goto done;
        }

        if (retval != 0)
            goto done;
    }

done:
    return NULL;
}

OE_INLINE void _set_err(int* err, int num)
{
    if (err)
        *err = num;
}

int oe_polling_epoll_create1(int flags, int* err)
{
    int ret = epoll_create1(flags);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_polling_epoll_wait(
    int64_t enclaveid,
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout,
    int* err)
{
    int ret = -1;
    size_t eventsize;
    pthread_t thread = 0;
    wait_args_t* args = NULL;

    (void)events;
    (void)timeout;

    /* ATTN: how does this work without using the events parameter. */

    eventsize = sizeof(struct oe_epoll_event) * maxevents;

    if (!(args = calloc(1, sizeof(wait_args_t) + eventsize)))
    {
        _set_err(err, ENOMEM);
        goto done;
    }

    args->enclaveid = enclaveid;
    args->epfd = epfd;
    args->maxevents = (int)maxevents;

    // We lose the wait thread when we exit the func, but the thread will die
    // on its own copy args then spawn pthread to do the waiting. That way we
    // can ecall with notification. the thread args are freed by the thread
    // func.
    if (pthread_create(&thread, NULL, epoll_wait_thread, args) < 0)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int oe_polling_epoll_ctl_add(
    int epfd,
    int fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd,
    int* err)
{
    int ret = -1;

    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)epoll_enclave_fd,
    };

    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_polling_epoll_ctl_del(int epfd, int fd, int* err)
{
    int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_polling_epoll_ctl_mod(
    int epfd,
    int fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd,
    int* err)
{
    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)enclave_fd,
    };

    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    int ret = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_polling_epoll_close(int fd, int* err)
{
    int ret = close(fd);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_polling_shutdown_device(int fd, int* err)
{
    (void)fd;
    (void)err;

    /* ATTN: implement this */
    return -1;
}
