// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>

#define DIR_MAGIC 0x09180827

struct _OE_DIR
{
    uint32_t magic;
    int fd;
    struct oe_dirent buf;
};

static oe_device_t* _get_fs_device(uint64_t devid)
{
    oe_device_t* ret = NULL;
    oe_device_t* device = oe_get_devid_device(devid);

    if (!device || device->type != OE_DEVICETYPE_FILESYSTEM)
        goto done;

    ret = device;

done:
    return ret;
}

int oe_open(const char* pathname, int flags, mode_t mode)
{
    int ret = -1;
    int fd;
    oe_device_t* fs;
    oe_device_t* file;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (!(file = (*fs->ops.fs->open)(fs, filepath, flags, mode)))
        goto done;

    if ((fd = oe_assign_fd_device(file)) == -1)
    {
        (*fs->ops.fs->base.close)(file);
        goto done;
    }

    ret = fd;

done:
    return ret;
}

int oe_open_d(uint64_t devid, const char* pathname, int flags, mode_t mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_open(pathname, flags, mode);
    }
    else
    {
        oe_device_t* dev;
        oe_device_t* file;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (!(file = (*dev->ops.fs->open)(dev, pathname, flags, mode)))
            goto done;

        if ((ret = oe_assign_fd_device(file)) == -1)
        {
            (*dev->ops.fs->base.close)(file);
            goto done;
        }
    }

done:
    return ret;
}

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname)
{
    OE_DIR* ret = NULL;
    OE_DIR* dir = NULL;
    int fd = -1;

    if (!(dir = oe_calloc(1, sizeof(OE_DIR))))
    {
        oe_errno = ENOMEM;
        goto done;
    }

    if ((fd = oe_open_d(devid, pathname, OE_O_RDONLY | OE_O_DIRECTORY, 0)) < 0)
    {
        goto done;
    }

    dir->magic = DIR_MAGIC;
    dir->fd = fd;

    ret = dir;
    dir = NULL;
    fd = -1;

done:

    if (dir)
        oe_free(dir);

    if (fd >= 0)
        oe_close(fd);

    return ret;
}

OE_DIR* oe_opendir(const char* pathname)
{
    return oe_opendir_d(OE_DEVID_NULL, pathname);
}

struct oe_dirent* oe_readdir(OE_DIR* dir)
{
    struct oe_dirent* ret = NULL;
    unsigned int count = (unsigned int)sizeof(struct oe_dirent);

    if (!dir || dir->magic != DIR_MAGIC)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_getdents((unsigned int)dir->fd, &dir->buf, count) != (int)count)
        goto done;

    ret = &dir->buf;

done:
    return ret;
}

int oe_closedir(OE_DIR* dir)
{
    int ret = -1;

    if (!dir || dir->magic != DIR_MAGIC)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if ((ret = oe_close(dir->fd)) == 0)
    {
        dir->magic = 0;
    }

done:
    return ret;
}

void oe_rewinddir(OE_DIR* dir)
{
    if (dir && dir->magic == DIR_MAGIC)
    {
        oe_lseek(dir->fd, 0, OE_SEEK_SET);
    }
}

int oe_rmdir(const char* pathname)
{
    int ret = -1;
    oe_device_t* fs;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (fs->ops.fs->rmdir == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->rmdir)(fs, filepath);

done:
    return ret;
}

int oe_stat(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    oe_device_t* fs;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (fs->ops.fs->stat == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->stat)(fs, filepath, buf);

done:
    return ret;
}

int oe_link(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs;
    oe_device_t* newfs;
    char filepath[OE_PATH_MAX] = {0};
    char newfilepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(oldpath, filepath)))
        goto done;

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
        goto done;

    if (fs != newfs)
    {
        oe_errno = EXDEV;
        goto done;
    }

    if (fs->ops.fs->link == NULL)
    {
        oe_errno = EPERM;
        goto done;
    }

    ret = (*fs->ops.fs->link)(fs, filepath, newfilepath);

done:
    return ret;
}

int oe_unlink(const char* pathname)
{
    int ret = -1;
    oe_device_t* fs;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (fs->ops.fs->unlink == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->unlink)(fs, filepath);

done:
    return ret;
}

int oe_rename(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs;
    oe_device_t* newfs;
    char filepath[OE_PATH_MAX];
    char newfilepath[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(oldpath, filepath)))
        goto done;

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
        goto done;

    if (fs != newfs)
    {
        oe_errno = EXDEV;
        goto done;
    }

    if (fs->ops.fs->rename == NULL)
    {
        oe_errno = EPERM;
        goto done;
    }

    ret = (*fs->ops.fs->rename)(fs, filepath, newfilepath);

done:
    return ret;
}

int oe_truncate(const char* pathname, off_t length)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (fs->ops.fs->truncate == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->truncate)(fs, filepath, length);

done:
    return ret;
}

int oe_mkdir(const char* pathname, mode_t mode)
{
    int ret = -1;
    oe_device_t* fs;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        goto done;

    if (fs->ops.fs->mkdir == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->mkdir)(fs, filepath, mode);

done:
    return ret;
}

off_t oe_lseek(int fd, off_t offset, int whence)
{
    off_t ret = -1;
    oe_device_t* file;

    if (!(file = oe_get_fd_device(fd)))
    {
        oe_errno = EBADF;
        goto done;
    }

    if (file->ops.fs->lseek == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*file->ops.fs->lseek)(file, offset, whence);

done:
    return ret;
}

int oe_getdents(unsigned int fd, struct oe_dirent* dirp, unsigned int count)
{
    int ret = -1;
    oe_device_t* file;

    if (!(file = oe_get_fd_device((int)fd)))
    {
        oe_errno = EBADF;
        goto done;
    }

    if (file->ops.fs->getdents == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*file->ops.fs->getdents)(file, dirp, count);

done:
    return ret;
}

ssize_t oe_readv(int fd, const struct oe_iovec* iov, int iovcnt)
{
    ssize_t ret = -1;
    ssize_t nread = 0;

    if (fd < 0 || !iov)
    {
        oe_errno = EINVAL;
        goto done;
    }

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_read(fd, p->iov_base, p->iov_len);

        if (n < 0)
            goto done;

        nread += n;

        if ((size_t)n < p->iov_len)
            break;
    }

    ret = nread;

done:
    return ret;
}

ssize_t oe_writev(int fd, const struct oe_iovec* iov, int iovcnt)
{
    ssize_t ret = -1;
    ssize_t nwritten = 0;

    if (fd < 0 || !iov)
    {
        oe_errno = EINVAL;
        goto done;
    }

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_write(fd, p->iov_base, p->iov_len);

        if ((size_t)n != p->iov_len)
        {
            oe_errno = EIO;
            goto done;
        }

        nwritten += n;
    }

    ret = nwritten;

done:
    return ret;
}

int oe_access(const char* pathname, int mode)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char suffix[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(pathname, suffix)))
        goto done;

    if (fs->ops.fs->access == NULL)
    {
        oe_errno = EINVAL;
        goto done;
    }

    ret = (*fs->ops.fs->access)(fs, suffix, mode);

done:
    return ret;
}

int oe_unlink_d(uint64_t devid, const char* pathname)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_unlink(pathname);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->unlink(dev, pathname);
    }

done:
    return ret;
}

int oe_link_d(uint64_t devid, const char* oldpath, const char* newpath)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_link(oldpath, newpath);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->link(dev, oldpath, newpath);
    }

done:
    return ret;
}

int oe_rename_d(uint64_t devid, const char* oldpath, const char* newpath)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_rename(oldpath, newpath);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->rename(dev, oldpath, newpath);
    }

done:
    return ret;
}

int oe_mkdir_d(uint64_t devid, const char* pathname, mode_t mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_mkdir(pathname, mode);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->mkdir(dev, pathname, mode);
    }

done:
    return ret;
}

int oe_rmdir_d(uint64_t devid, const char* pathname)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_rmdir(pathname);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->rmdir(dev, pathname);
    }

done:
    return ret;
}

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat* buf)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_stat(pathname, buf);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->stat(dev, pathname, buf);
    }

done:
    return ret;
}

int oe_truncate_d(uint64_t devid, const char* path, off_t length)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_truncate(path, length);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = dev->ops.fs->truncate(dev, path, length);
    }

done:
    return ret;
}

int oe_access_d(uint64_t devid, const char* pathname, int mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NULL)
    {
        ret = oe_access(pathname, mode);
    }
    else
    {
        oe_device_t* dev;
        struct oe_stat buf;

        if (!(dev = _get_fs_device(devid)))
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (!pathname)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (oe_stat(pathname, &buf) != 0)
        {
            oe_errno = ENOENT;
            goto done;
        }

        ret = 0;
    }

done:
    return ret;
}
