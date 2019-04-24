// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/ctype.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/defs.h>

size_t oe_strlen(const char* s)
{
    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return (size_t)(p - s);
    if (!p[1])
        return (size_t)(p - s + 1);
    if (!p[2])
        return (size_t)(p - s + 2);
    if (!p[3])
        return (size_t)(p - s + 3);
    if (!p[4])
        return (size_t)(p - s + 4);
    if (!p[5])
        return (size_t)(p - s + 5);

    /* Unreachable */
    return 0;
}

size_t oe_strnlen(const char* s, size_t n)
{
    const char* p = s;

    while (n-- && *p)
        p++;

    return (size_t)(p - s);
}

int oe_strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int oe_strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

size_t oe_strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return (size_t)(src - start);
}

char* oe_strncpy(char* dest, const char* src, size_t n)
{
    char* ret = dest;

    /* Copy at most n bytes. Terminate when src is exhausted. */
    while (n-- && *src)
        *dest++ = *src++;

    /* If there is room left, then inject zero-terminator. */
    if (n)
        *dest = '\0';

    return ret;
}

size_t oe_strlcat(char* dest, const char* src, size_t size)
{
    size_t n = 0;

    if (size)
    {
        char* end = dest + size - 1;

        while (*dest && dest != end)
        {
            dest++;
            n++;
        }

        while (*src && dest != end)
        {
            n++;
            *dest++ = *src++;
        }

        *dest = '\0';
    }

    while (*src)
    {
        src++;
        n++;
    }

    return n;
}

char* oe_strstr(const char* haystack, const char* needle)
{
    size_t hlen = oe_strlen(haystack);
    size_t nlen = oe_strlen(needle);

    if (nlen > hlen)
        return NULL;

    for (size_t i = 0; i < hlen - nlen + 1; i++)
    {
        if (memcmp(haystack + i, needle, nlen) == 0)
            return (char*)haystack + i;
    }

    return NULL;
}

char* oe_strdup(const char* s)
{
    size_t len;
    char* p;

    if (!s)
        return NULL;

    len = oe_strlen(s);

    if (!(p = oe_malloc(len + 1)))
        return NULL;

    return memcpy(p, s, len + 1);
}

OE_WEAK_ALIAS(oe_strcmp, strcmp);

int oe_strcasecmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (oe_toupper(*s1) == oe_toupper(*s2)))
    {
        s1++;
        s2++;
    }

    return oe_toupper(*s1) - oe_toupper(*s2);
}

int oe_strncasecmp(const char* s1, const char* s2, size_t n)
{
    while (n && *s1 && *s2 && oe_toupper(*s1) == oe_toupper(*s2))
    {
        n--;
        s1++;
        s2++;
    }

    if (n == 0)
        return 0;

    if (!*s1)
        return -1;

    if (!*s2)
        return 1;

    return oe_toupper(*s1) - oe_toupper(*s2);
}

char* oe_strchr(const char* s, int c)
{
    while (*s && *s != c)
        s++;

    if (*s == c)
        return (char*)s;

    return NULL;
}

char* oe_strrchr(const char* s, int c)
{
    char* p = (char*)s + oe_strlen(s);

    if (c == '\0')
        return p;

    while (p != s)
    {
        if (*--p == c)
            return p;
    }

    return NULL;
}

int oe_atoi(const char* nptr)
{
    return (int)oe_strtol(nptr, NULL, 10);
}

char* oe_strchrnul(const char* s, int c)
{
    char* p;

    if (!(p = oe_strchr(s, c)))
        p = (char*)(s + oe_strlen(s));

    return p;
}

size_t oe_strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!oe_strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

size_t oe_strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (oe_strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}
