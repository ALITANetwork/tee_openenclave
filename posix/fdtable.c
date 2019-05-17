// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/module.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/posix/fd.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "consolefs.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

/* The table allocation grows in multiples of the chunk size. */
#define TABLE_CHUNK_SIZE 1024

/* Define a table of file-descriptors. */
typedef oe_fd_t* entry_t;
static entry_t* _table;
static size_t _table_size;
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

static void _atexit_handler(void)
{
    /* Free the standard fds (but do not close them). */
    for (size_t i = 0; i <= OE_STDERR_FILENO; i++)
    {
        oe_fd_t* desc = _table[i];

        if (desc)
            oe_free(desc);
    }

    oe_free(_table);
}

static int _resize_table(size_t new_size)
{
    int ret = -1;

    /* The fdtable cannot be bigger than the maximum int file descriptor. */
    if (new_size > OE_INT_MAX)
        goto done;

    /* Round the new capacity up to the next multiple of the chunk size. */
    new_size = oe_round_up_to_multiple(new_size, TABLE_CHUNK_SIZE);

    if (new_size > OE_INT_MAX)
        new_size = OE_INT_MAX;

    if (new_size > _table_size)
    {
        entry_t* p;
        size_t n = new_size;

        /* Reallocate the table. */
        if (!(p = oe_realloc(_table, n * sizeof(entry_t))))
            goto done;

        /* Zero-fill the unused portion. */
        {
            const size_t num_bytes = (n - _table_size) * sizeof(entry_t);

            if (oe_memset_s(p + _table_size, num_bytes, 0, num_bytes) != OE_OK)
                goto done;
        }

        _table = p;
        _table_size = new_size;
    }

    ret = 0;

done:
    return ret;
}

static int _initialize(void)
{
    int ret = -1;
    static bool _initialized;

    /* Do this the first time only. */
    if (!_initialized)
    {
        /* Make the table more than large enough for standard files. */
        if (_resize_table(TABLE_CHUNK_SIZE) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);

        /* Create the STDIN file. */
        {
            oe_fd_t* file;

            if (!(file = oe_consolefs_create_file(OE_STDIN_FILENO)))
                OE_RAISE_ERRNO(OE_ENOMEM);

            _table[OE_STDIN_FILENO] = file;
        }

        /* Create the STDOUT file. */
        {
            oe_fd_t* file;

            if (!(file = oe_consolefs_create_file(OE_STDOUT_FILENO)))
                OE_RAISE_ERRNO(OE_ENOMEM);

            _table[OE_STDOUT_FILENO] = file;
        }

        /* Create the STDERR file. */
        {
            oe_fd_t* file;

            if (!(file = oe_consolefs_create_file(OE_STDERR_FILENO)))
                OE_RAISE_ERRNO(OE_ENOMEM);

            _table[OE_STDERR_FILENO] = file;
        }

        /* Install the atexit handler that will release the table. */
        oe_atexit(_atexit_handler);

        _initialized = true;
    }

    ret = 0;

done:

    return ret;
}

/* Raise and log an error if the condition is false. */
#define CHECK_CONDITION(COND)                                         \
    do                                                                \
    {                                                                 \
        if (!(COND))                                                  \
            OE_RAISE_ERRNO_MSG(OE_EINVAL, "failed check: %s", #COND); \
    } while (0)

static int _check_fd(oe_fd_t* desc)
{
    int ret = -1;

    CHECK_CONDITION(desc->ops.fd.read);
    CHECK_CONDITION(desc->ops.fd.write);
    CHECK_CONDITION(desc->ops.fd.dup);
    CHECK_CONDITION(desc->ops.fd.ioctl);
    CHECK_CONDITION(desc->ops.fd.fcntl);
    CHECK_CONDITION(desc->ops.fd.close);
    CHECK_CONDITION(desc->ops.fd.get_host_fd);

    switch (desc->type)
    {
        case OE_FD_TYPE_NONE:
        case OE_FD_TYPE_ANY:
        {
            goto done;
        }
        case OE_FD_TYPE_FILE:
        {
            CHECK_CONDITION(desc->ops.file.lseek);
            CHECK_CONDITION(desc->ops.file.getdents);
            break;
        }
        case OE_FD_TYPE_SOCKET:
        {
            CHECK_CONDITION(desc->ops.socket.connect);
            CHECK_CONDITION(desc->ops.socket.accept);
            CHECK_CONDITION(desc->ops.socket.bind);
            CHECK_CONDITION(desc->ops.socket.listen);
            CHECK_CONDITION(desc->ops.socket.send);
            CHECK_CONDITION(desc->ops.socket.recv);
            CHECK_CONDITION(desc->ops.socket.sendto);
            CHECK_CONDITION(desc->ops.socket.recvfrom);
            CHECK_CONDITION(desc->ops.socket.sendmsg);
            CHECK_CONDITION(desc->ops.socket.recvmsg);
            CHECK_CONDITION(desc->ops.socket.shutdown);
            CHECK_CONDITION(desc->ops.socket.getsockopt);
            CHECK_CONDITION(desc->ops.socket.setsockopt);
            CHECK_CONDITION(desc->ops.socket.getpeername);
            CHECK_CONDITION(desc->ops.socket.getsockname);
            break;
        }
        case OE_FD_TYPE_EPOLL:
        {
            CHECK_CONDITION(desc->ops.epoll.epoll_ctl);
            CHECK_CONDITION(desc->ops.epoll.epoll_wait);
            break;
        }
        case OE_FD_TYPE_EVENTFD:
        {
            break;
        }
    }

    ret = 0;

done:
    return ret;
}

/*
**==============================================================================
**
** Public interface:
**
**==============================================================================
*/

int oe_fdtable_assign(oe_fd_t* desc)
{
    int ret = -1;
    size_t index;

    oe_spin_lock(&_lock);

    if (_initialize() != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (!desc)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_check_fd(desc) != 0)
        OE_RAISE_ERRNO_MSG(OE_EINVAL, "bad desc parameter: %u\n", desc->type);

    /* Find the first available file descriptor. */
    for (index = 0; index < _table_size; index++)
    {
        if (!_table[index])
            break;
    }

    /* If no free slot found, expand size of the file descriptor table. */
    if (index == _table_size)
    {
        if (_resize_table(_table_size + 1) != 0)
            OE_RAISE_ERRNO(OE_ENOMEM);
    }

    _table[index] = desc;
    ret = (int)index;

done:

    oe_spin_unlock(&_lock);

    return ret;
}

int oe_fdtable_release(int fd)
{
    int ret = -1;

    oe_spin_lock(&_lock);

    if (_initialize() != 0)
        OE_RAISE_ERRNO(oe_errno);

    /* Fail if fd is out of range. */
    if (!(fd >= 0 && (size_t)fd < _table_size))
        OE_RAISE_ERRNO(OE_EBADF);

    /* Fail if entry was never assigned. */
    if (!_table[fd])
        OE_RAISE_ERRNO(OE_EINVAL);

    _table[fd] = NULL;

    ret = 0;

done:

    oe_spin_unlock(&_lock);

    return ret;
}

int oe_fdtable_reassign(int fd, oe_fd_t* desc)
{
    int ret = -1;

    oe_spin_lock(&_lock);

    if (_initialize() != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (desc && _check_fd(desc) != 0)
        OE_RAISE_ERRNO_MSG(OE_EINVAL, "bad desc parameter: %u\n", desc->type);

    /* Make table big enough to contain this file-descriptor. */
    if (fd >= 0)
        _resize_table((size_t)fd + 1);

    if (fd < 0 || (size_t)fd >= _table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    if (_table[fd])
    {
        if (_table[fd]->ops.fd.close(_table[fd]) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Set the fd. */
    _table[fd] = desc;

    ret = 0;

done:

    oe_spin_unlock(&_lock);

    return ret;
}

static oe_fd_t* _get_fd(int fd)
{
    oe_fd_t* ret = NULL;

    oe_spin_lock(&_lock);

    if (_initialize() != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (fd < 0 || (size_t)fd >= _table_size)
        OE_RAISE_ERRNO(OE_EBADF);

    if (_table[fd] == NULL)
        OE_RAISE_ERRNO(OE_EBADF);

    ret = _table[fd];

done:

    oe_spin_unlock(&_lock);

    return ret;
}

oe_fd_t* oe_fdtable_get(int fd, oe_fd_type_t type)
{
    oe_fd_t* ret = NULL;
    oe_fd_t* desc;

    if (!(desc = _get_fd(fd)))
        OE_RAISE_ERRNO(OE_EBADF);

    if (type != OE_DEVICE_TYPE_ANY && desc->type != type)
    {
        OE_RAISE_ERRNO_MSG(
            OE_EBADF, "fd=%d type=%u fd->type=%u", fd, type, desc->type);
    }

    ret = desc;

done:
    return ret;
}
