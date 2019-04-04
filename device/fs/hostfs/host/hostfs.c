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
#include "oe_u.h"

int oe_hostfs_open(const char* pathname, int flags, mode_t mode, int* err)
{
    int ret = -1;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & 0x00000003) != OE_O_RDONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDIN_FILENO;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDOUT_FILENO;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDERR_FILENO;
    }
    else
    {
        ret = open(pathname, flags, mode);

        if (ret == -1 && err)
            *err = errno;
    }

done:
    return ret;
}

ssize_t oe_hostfs_read(int fd, void* buf, size_t count, int* err)
{
    ssize_t ret = read(fd, buf, count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

ssize_t oe_hostfs_write(int fd, const void* buf, size_t count, int* err)
{
    ssize_t ret = write(fd, buf, count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

off_t oe_hostfs_lseek(int fd, off_t offset, int whence, int* err)
{
    off_t ret = lseek(fd, offset, whence);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_close(int fd, int* err)
{
    int ret = close(fd);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_dup(int oldfd, int* err)
{
    int ret = dup(oldfd);

    if (ret < 0 && err)
        *err = errno;

    return ret;
}

void* oe_hostfs_opendir(const char* name, int* err)
{
    void* ret = opendir(name);

    if (!ret && err)
        *err = errno;

    return ret;
}

int oe_hostfs_readdir(void* dirp, struct oe_hostfs_dirent_struct* buf, int* err)
{
    int ret = -1;
    struct dirent* ent = readdir((DIR*)dirp);

    if (!buf)
    {
        if (err)
            *err = EBADF;

        goto done;
    }

    if (!ent)
    {
        goto done;
    }

    memset(buf, 0, sizeof(struct oe_hostfs_dirent_struct));
    buf->d_ino = ent->d_ino;
    buf->d_off = ent->d_off;
    buf->d_reclen = ent->d_reclen;
    buf->d_type = ent->d_type;
    strncat(buf->d_name, ent->d_name, sizeof(buf->d_name) - 1);

    ret = 0;

done:
    return ret;
}

void oe_hostfs_rewinddir(void* dirp)
{
    rewinddir((DIR*)dirp);
}

int oe_hostfs_closedir(void* dirp, int* err)
{
    int ret = closedir((DIR*)dirp);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_stat(
    const char* pathname,
    struct oe_hostfs_stat_struct* buf,
    int* err)
{
    struct stat st;
    int ret;

    if (buf)
        memset(buf, 0, sizeof(*buf));

    ret = stat(pathname, &st);

    if (ret == 0)
    {
        buf->st_dev = st.st_dev;
        buf->st_ino = st.st_ino;
        buf->st_nlink = st.st_nlink;
        buf->st_mode = st.st_mode;
        buf->st_uid = st.st_uid;
        buf->st_gid = st.st_gid;
        buf->st_rdev = st.st_rdev;
        buf->st_size = st.st_size;
        buf->st_blksize = st.st_blksize;
        buf->st_blocks = st.st_blocks;
        buf->st_atim.tv_sec = st.st_atim.tv_sec;
        buf->st_atim.tv_nsec = st.st_atim.tv_nsec;
        buf->st_mtim.tv_sec = st.st_mtim.tv_sec;
        buf->st_mtim.tv_nsec = st.st_mtim.tv_nsec;
        buf->st_ctim.tv_sec = st.st_ctim.tv_sec;
        buf->st_ctim.tv_nsec = st.st_ctim.tv_nsec;
    }
    else
    {
        if (ret != 0 && err)
            *err = errno;
    }

    return ret;
}

int oe_hostfs_access(const char* pathname, int mode, int* err)
{
    int ret = access(pathname, mode);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_link(const char* oldpath, const char* newpath, int* err)
{
    int ret = link(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_unlink(const char* pathname, int* err)
{
    int ret = unlink(pathname);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_rename(const char* oldpath, const char* newpath, int* err)
{
    int ret = rename(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_truncate(const char* path, off_t length, int* err)
{
    int ret = truncate(path, length);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_mkdir(const char* pathname, mode_t mode, int* err)
{
    int ret = mkdir(pathname, mode);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_hostfs_rmdir(const char* pathname, int* err)
{
    int ret = rmdir(pathname);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}
