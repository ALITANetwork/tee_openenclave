// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <openenclave/enclave.h>

#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/assert.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/thread.h>

#define MAGIC 0xe437a308
#define BUFFER_SIZE (OE_BUFSIZ * 4)

struct _OE_IO_FILE
{
    uint32_t magic;
    int fd;
    uint8_t inbuf[BUFFER_SIZE];
    size_t inbuf_size;
    uint8_t outbuf[BUFFER_SIZE];
    size_t outbuf_size;
    oe_spinlock_t lock;
    bool err;
    bool eof;
};

static OE_FILE _stdin = {
    .magic = MAGIC,
    .fd = OE_STDIN_FILENO,
};

static OE_FILE _stdout = {
    .magic = MAGIC,
    .fd = OE_STDOUT_FILENO,
};

static OE_FILE _stderr = {
    .magic = MAGIC,
    .fd = OE_STDERR_FILENO,
};

OE_FILE* const oe_stdin = &_stdin;
OE_FILE* const oe_stdout = &_stdout;
OE_FILE* const oe_stderr = &_stderr;

static bool _valid(const OE_FILE* stream)
{
    return stream && stream->magic == MAGIC && stream->fd >= 0;
}

static ssize_t _read_n(int fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    uint8_t* p = (uint8_t*)buf;
    size_t r = count;
    ssize_t nread = 0;

    while (r)
    {
        ssize_t n = oe_read(fd, p, r);

        if (n == -1)
            goto done;

        if (n == 0)
            break;

        p += n;
        r -= (size_t)n;
        nread += n;
    }

    ret = nread;

done:
    return ret;
}

static ssize_t _write_n(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    const uint8_t* p = (const uint8_t*)buf;
    size_t r = count;
    ssize_t nwritten = 0;

    while (r)
    {
        ssize_t n = oe_write(fd, p, r);

        if (n <= 0)
            goto done;

        p += n;
        r -= (size_t)n;
        nwritten += n;
    }

    ret = nwritten;

done:
    return ret;
}

OE_FILE* oe_fopen(const char* path, const char* mode)
{
    OE_FILE* ret = NULL;
    OE_FILE* stream = NULL;
    int flags;
    int fd;
    static const size_t MODE_BUF_SIZE = 8;
    static const mode_t CREATE_MODE = 0666;

    /* Reject bad parameters. */
    if (!path || !mode || oe_strlen(mode) >= MODE_BUF_SIZE)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Translate the mode string to open flags. */
    {
        char buf[MODE_BUF_SIZE];

        /* Strip 'b' from the buf parameter. */
        {
            const char* src = mode;
            char* dest = buf;

            while (*src)
            {
                if (*src != 'b')
                    *dest++ = *src;

                src++;
            }

            *dest = '\0';
        }

        if (oe_strcmp(buf, "r") == 0)
        {
            flags = OE_O_RDONLY;
        }
        else if (oe_strcmp(buf, "r+") == 0)
        {
            flags = OE_O_RDWR;
        }
        else if (oe_strcmp(buf, "w") == 0)
        {
            flags = OE_O_WRONLY | OE_O_TRUNC | OE_O_CREAT;
        }
        else if (oe_strcmp(buf, "w+") == 0)
        {
            flags = OE_O_RDWR | OE_O_TRUNC | OE_O_CREAT;
        }
        else if (oe_strcmp(buf, "a") == 0)
        {
            flags = OE_O_WRONLY | OE_O_APPEND | OE_O_CREAT;
        }
        else if (oe_strcmp(buf, "a+") == 0)
        {
            flags = OE_O_RDWR | OE_O_APPEND | OE_O_CREAT;
        }
        else
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    /* Create the file object. */
    if (!(stream = oe_calloc(1, sizeof(OE_FILE))))
    {
        oe_errno = ENOMEM;
        goto done;
    }

    /* Open the OEFS file. */
    if ((fd = oe_open(path, flags, CREATE_MODE)) == -1)
    {
        goto done;
    }

    /* Initialize the stream object. */
    stream->magic = MAGIC;
    stream->fd = fd;
    ret = stream;
    stream = NULL;

done:

    if (stream)
        oe_free(stream);

    return ret;
}

int oe_fflush(OE_FILE* stream)
{
    int ret = OE_EOF;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (stream->outbuf_size)
    {
        ssize_t n = _write_n(stream->fd, stream->outbuf, stream->outbuf_size);

        if (n == -1)
            goto done;

        if ((size_t)n != stream->outbuf_size)
            goto done;

        stream->outbuf_size = 0;
    }

    ret = 0;

done:
    return ret;
}

int oe_fclose(OE_FILE* stream)
{
    int ret = -1;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_fflush(stream) != 0)
    {
        goto done;
    }

    if (oe_close(stream->fd) != 0)
    {
        goto done;
    }

    memset(stream, 0, sizeof(OE_FILE));
    ret = 0;

done:
    return ret;
}

size_t oe_fread(void* ptr_, size_t size, size_t nmemb, OE_FILE* stream)
{
    size_t ret = 0;
    size_t count;
    ssize_t nread = 0;
    uint8_t* ptr = (uint8_t*)ptr_;

    if (oe_safe_mul_u64(size, nmemb, &count) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!ptr || !_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (count == 0)
    {
        goto done;
    }

    /* Flush the write buffer before reading. */
    if (oe_fflush(stream) != 0)
    {
        stream->err = true;
        goto done;
    }

    /* Read from the input buffer until caller's buffer is full. */
    while (count > 0)
    {
        /* Read from the input buffer first. */
        if (stream->inbuf_size)
        {
            size_t n;

            if (count <= stream->inbuf_size)
                n = count;
            else
                n = stream->inbuf_size;

            memcpy(ptr, stream->inbuf, n);
            ptr += n;
            count -= n;
            nread += n;

            memmove(stream->inbuf, stream->inbuf + n, stream->inbuf_size - n);

            stream->inbuf_size -= n;
        }

        /* Replinish the input buffer if it is depleted. */
        if (count > 0)
        {
            ssize_t n;

            /* This is a logic error and should not happen. */
            if (stream->inbuf_size != 0)
            {
                oe_errno = EINVAL;
                goto done;
            }

            /* Break out if already at end of file. */
            if (stream->eof)
                break;

            /* Read into the input buffer. */
            if ((n = _read_n(stream->fd, stream->inbuf, BUFFER_SIZE)) == -1)
            {
                stream->err = true;
                goto done;
            }

            /* Set flag to indicate that the end-of-file reached. */
            if ((size_t)n < BUFFER_SIZE)
            {
                stream->eof = true;
            }

            /* Increment input buffer size. */
            stream->inbuf_size += (size_t)n;
        }
    }

    ret = (size_t)nread / size;

    if (ret == 0)
        stream->eof = true;

done:

    return ret;
}

size_t oe_fwrite(const void* ptr_, size_t size, size_t nmemb, OE_FILE* stream)
{
    size_t ret = 0;
    size_t count;
    const uint8_t* ptr = (const uint8_t*)ptr_;

    /* Fail if the product of size and nmemb overflows. */
    if (oe_safe_mul_u64(size, nmemb, &count) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Check for invalid parameters. */
    if (!_valid(stream) || !ptr)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Discard the input buffer. */
    stream->inbuf_size = 0;

    /* While there are more bytes to be written. */
    while (count > 0)
    {
        size_t r = BUFFER_SIZE - stream->outbuf_size;
        size_t n = (count < r) ? count : r;

        /* Copy more caller data into the output buffer. */
        memcpy(&stream->outbuf[stream->outbuf_size], ptr, n);
        ptr += n;
        count -= n;
        stream->outbuf_size += n;

        /* Flush the output buffer if it is full. */
        if (stream->outbuf_size == BUFFER_SIZE)
        {
            if (oe_fflush(stream) == OE_EOF)
            {
                stream->eof = true;
                stream->err = true;
                goto done;
            }
        }

        ret += n;
    }

done:

    return ret;
}

long oe_ftell(OE_FILE* stream)
{
    long ret = -1;
    off_t r;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if ((r = oe_lseek(stream->fd, 0, OE_SEEK_CUR)) == (off_t)-1)
        goto done;

    ret = (long)r;

done:
    return ret;
}

int oe_fseek(OE_FILE* stream, long offset, int whence)
{
    int ret = -1;
    off_t r;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_fflush(stream) != 0)
    {
        stream->err = true;
        goto done;
    }

    /* Discard the input buffer. */
    stream->inbuf_size = 0;

    if ((r = oe_lseek(stream->fd, offset, whence)) == (off_t)-1)
        goto done;

    ret = 0;

done:
    return ret;
}

int oe_ferror(OE_FILE* stream)
{
    int ret = 1;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (stream->err)
        goto done;

    ret = 0;

done:
    return ret;
}

int oe_feof(OE_FILE* stream)
{
    int ret = 1;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (stream->eof)
        goto done;

    ret = 0;

done:
    return ret;
}

void oe_clearerr(OE_FILE* stream)
{
    if (_valid(stream))
    {
        stream->eof = false;
        stream->err = false;
    }
}

int oe_fgetc(OE_FILE* stream)
{
    int ret = OE_EOF;
    char c;

    if (!_valid(stream))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_fread(&c, sizeof(c), 1, stream) != 1)
        goto done;

    ret = c;

done:
    return ret;
}

char* oe_fgets(char* s, int size, OE_FILE* stream)
{
    char* ret = NULL;
    char* p = s;
    int n = size;
    int c;
    int count = 0;

    if (!s || !_valid(stream) || size < 1)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Leave room for the zero-terminator. */
    n--;

    while (n && (c = oe_fgetc(stream)) != OE_EOF)
    {
        *p++ = (char)c;
        n--;
        count++;

        if (c == '\n')
            break;
    }

    if (count == 0)
        goto done;

    /* Zero-terminate the buffer. */
    *p = '\0';

    ret = s;

done:
    return ret;
}
