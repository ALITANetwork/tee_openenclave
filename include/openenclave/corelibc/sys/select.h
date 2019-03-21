// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_SELECT_H
#define _OE_SYS_SELECT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/sys/time.h>
#include <openenclave/corelibc/time.h>
#include <unistd.h>

OE_EXTERNC_BEGIN

#define OE_FD_SETSIZE 1024

typedef struct
{
#include <openenclave/corelibc/sys/bits/fd_set.h>
} oe_fd_set;

int oe_select(
    int nfds,
    oe_fd_set* readfds,
    oe_fd_set* writefds,
    oe_fd_set* exceptfds,
    struct oe_timeval* timeout);

void OE_FD_CLR(int fd, oe_fd_set* set);

int OE_FD_ISSET(int fd, oe_fd_set* set);

void OE_FD_SET(int fd, oe_fd_set* set);

void OE_FD_ZERO(oe_fd_set* set);

#if defined(OE_NEED_STDC_NAMES)

#define FD_SETSIZE 1024

typedef struct
{
#include <openenclave/corelibc/sys/bits/fd_set.h>
} fd_set;

OE_INLINE int select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout)
{
    return oe_select(
        nfds,
        (oe_fd_set*)readfds,
        (oe_fd_set*)writefds,
        (oe_fd_set*)exceptfds,
        (struct oe_timeval*)timeout);
}

OE_INLINE void FD_CLR(int fd, fd_set* set)
{
    OE_FD_CLR(fd, (oe_fd_set*)set);
}

OE_INLINE int FD_ISSET(int fd, fd_set* set)
{
    return OE_FD_ISSET(fd, (oe_fd_set*)set);
}

OE_INLINE void FD_SET(int fd, fd_set* set)
{
    OE_FD_SET(fd, (oe_fd_set*)set);
}

OE_INLINE void FD_ZERO(fd_set* set)
{
    OE_FD_ZERO((oe_fd_set*)set);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_SELECT_H */
