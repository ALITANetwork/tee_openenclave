// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/hostfs.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../common/hostfsargs.h"

void oe_handle_hostfs_ocall(void* args_)
{
    oe_hostfs_args_t* args = (oe_hostfs_args_t*)args_;

    if (!args)
        return;

    errno = 0;

    switch (args->op)
    {
        case OE_HOSTFS_OP_NONE:
        {
            break;
        }
        case OE_HOSTFS_OP_OPEN:
        {
            if (strcmp(args->u.open.pathname, "/dev/stdin") == 0)
            {
                if ((args->u.open.flags & 0x00000003) != OE_O_RDONLY)
                {
                    errno = EINVAL;
                    break;
                }

                args->u.open.ret = OE_STDIN_FILENO;
            }
            else if (strcmp(args->u.open.pathname, "/dev/stdout") == 0)
            {
                if ((args->u.open.flags & 0x00000003) != OE_O_WRONLY)
                {
                    errno = EINVAL;
                    break;
                }

                args->u.open.ret = OE_STDOUT_FILENO;
            }
            else if (strcmp(args->u.open.pathname, "/dev/stderr") == 0)
            {
                if ((args->u.open.flags & 0x00000003) != OE_O_WRONLY)
                {
                    errno = EINVAL;
                    break;
                }

                args->u.open.ret = OE_STDERR_FILENO;
            }
            else
            {
                args->u.open.ret = open(
                    args->u.open.pathname,
                    args->u.open.flags,
                    args->u.open.mode);
            }
            break;
        }
        case OE_HOSTFS_OP_CLOSE:
        {
            args->u.close.ret = close(args->u.close.fd);
            break;
        }
        case OE_HOSTFS_OP_DUP:
        {
            args->u.dup.ret = dup((int)args->u.dup.host_fd);
            break;
        }
        case OE_HOSTFS_OP_READ:
        {
            args->u.read.ret =
                read(args->u.read.fd, args->buf, args->u.read.count);
            break;
        }
        case OE_HOSTFS_OP_WRITE:
        {
            args->u.read.ret =
                write(args->u.read.fd, args->buf, args->u.read.count);
            break;
        }
        case OE_HOSTFS_OP_LSEEK:
        {
            args->u.lseek.ret = lseek(
                args->u.lseek.fd, args->u.lseek.offset, args->u.lseek.whence);
            break;
        }
        case OE_HOSTFS_OP_OPENDIR:
        {
            args->u.opendir.ret = opendir(args->u.opendir.name);
            break;
        }
        case OE_HOSTFS_OP_READDIR:
        {
            struct dirent* result = readdir(args->u.readdir.dirp);

            if (result)
            {
                args->u.readdir.entry.d_ino = result->d_ino;
                args->u.readdir.entry.d_off = result->d_off;
                args->u.readdir.entry.d_reclen = result->d_reclen;
                args->u.readdir.entry.d_type = result->d_type;

                *args->u.readdir.entry.d_name = '\0';

                strncat(
                    args->u.readdir.entry.d_name,
                    result->d_name,
                    sizeof(args->u.readdir.entry.d_name) - 1);

                args->u.readdir.ret = &args->u.readdir.entry;
            }
            else
            {
                memset(
                    &args->u.readdir.entry, 0, sizeof(args->u.readdir.entry));
                args->u.readdir.ret = NULL;
            }
            break;
        }
        case OE_HOSTFS_OP_REWINDDIR:
        {
            rewinddir(args->u.rewinddir.dirp);
            break;
        }
        case OE_HOSTFS_OP_CLOSEDIR:
        {
            args->u.closedir.ret = closedir(args->u.closedir.dirp);
            break;
        }
        case OE_HOSTFS_OP_STAT:
        {
            struct stat buf;

            if ((args->u.stat.ret = stat(args->u.stat.pathname, &buf)) == 0)
            {
                args->u.stat.buf.st_dev = buf.st_dev;
                args->u.stat.buf.st_ino = buf.st_ino;
                args->u.stat.buf.st_mode = buf.st_mode;
                args->u.stat.buf.st_nlink = buf.st_nlink;
                args->u.stat.buf.st_uid = buf.st_uid;
                args->u.stat.buf.st_gid = buf.st_gid;
                args->u.stat.buf.st_rdev = buf.st_rdev;
                args->u.stat.buf.st_size = buf.st_size;
                args->u.stat.buf.st_blksize = buf.st_blksize;
                args->u.stat.buf.st_blocks = buf.st_blocks;
                args->u.stat.buf.st_atim.tv_sec = buf.st_atim.tv_sec;
                args->u.stat.buf.st_atim.tv_nsec = buf.st_atim.tv_nsec;
                args->u.stat.buf.st_mtim.tv_sec = buf.st_mtim.tv_sec;
                args->u.stat.buf.st_mtim.tv_nsec = buf.st_mtim.tv_nsec;
                args->u.stat.buf.st_ctim.tv_sec = buf.st_ctim.tv_sec;
                args->u.stat.buf.st_ctim.tv_nsec = buf.st_ctim.tv_nsec;
            }
            else
            {
                memset(&args->u.stat.buf, 0, sizeof(args->u.stat.buf));
            }
            break;
        }
        case OE_HOSTFS_OP_ACCESS:
        {
            args->u.access.ret =
                access(args->u.access.pathname, args->u.access.mode);
            break;
        }
        case OE_HOSTFS_OP_UNLINK:
        {
            args->u.unlink.ret = unlink(args->u.unlink.pathname);
            break;
        }
        case OE_HOSTFS_OP_LINK:
        {
            args->u.link.ret = link(args->u.link.oldpath, args->u.link.newpath);
            break;
        }
        case OE_HOSTFS_OP_RENAME:
        {
            args->u.rename.ret =
                rename(args->u.rename.oldpath, args->u.rename.newpath);
            break;
        }
        case OE_HOSTFS_OP_MKDIR:
        {
            args->u.mkdir.ret =
                mkdir(args->u.mkdir.pathname, args->u.mkdir.mode);
            break;
        }
        case OE_HOSTFS_OP_RMDIR:
        {
            args->u.rmdir.ret = rmdir(args->u.rmdir.pathname);
            break;
        }
        case OE_HOSTFS_OP_TRUNCATE:
        {
            args->u.truncate.ret =
                truncate(args->u.truncate.path, args->u.truncate.length);
            break;
        }
    }

    args->err = errno;
}
