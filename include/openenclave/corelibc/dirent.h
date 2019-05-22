// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DIRENT_H
#define _OE_DIRENT_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/limits.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

/* struct dirent d_type values. */
#define OE_DT_UNKNOWN 0
#define OE_DT_FIFO 1
#define OE_DT_CHR 2
#define OE_DT_DIR 4
#define OE_DT_BLK 6
#define OE_DT_REG 8
#define OE_DT_LNK 10
#define OE_DT_SOCK 12
#define OE_DT_WHT 14

typedef struct _OE_DIR OE_DIR;

#define __OE_DIRENT oe_dirent
#include <openenclave/corelibc/bits/dirent.h>
#undef __OE_DIRENT

OE_DIR* oe_opendir(const char* pathname);

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname);

struct oe_dirent* oe_readdir(OE_DIR* dir);

void oe_rewinddir(OE_DIR* dir);

int oe_closedir(OE_DIR* dir);

int oe_getdents64(unsigned int fd, struct oe_dirent* dirp, unsigned int count);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define DT_UNKNOWN OE_DT_UNKNOWN
#define DT_FIFO OE_DT_FIFO
#define DT_CHR OE_DT_CHR
#define DT_DIR OE_DT_DIR
#define DT_BLK OE_DT_BLK
#define DT_REG OE_DT_REG
#define DT_LNK OE_DT_LNK
#define DT_SOCK OE_DT_SOCK
#define DT_WHT OE_DT_WHT

#define __OE_DIRENT dirent
#include <openenclave/corelibc/bits/dirent.h>
#undef __OE_DIRENT

OE_INLINE DIR* opendir(const char* pathname)
{
    return (DIR*)oe_opendir(pathname);
}

OE_INLINE struct dirent* readdir(DIR* dir)
{
    return (struct dirent*)oe_readdir((OE_DIR*)dir);
}

OE_INLINE void rewinddir(DIR* dir)
{
    oe_rewinddir((OE_DIR*)dir);
}

OE_INLINE int closedir(DIR* dir)
{
    return oe_closedir((OE_DIR*)dir);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_DIRENT_H */
