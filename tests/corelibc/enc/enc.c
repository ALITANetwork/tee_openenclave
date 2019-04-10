// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <limits.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _OE_STDIO_H
#error "Please include the stdio.h from corelibc."
#endif

static const char* _lines[] = {
    "",
    "a",
    "",
    "bb",
    "",
    "ccc",
    "",
    "dddd",
    "",
};

static const size_t _nlines = OE_COUNTOF(_lines);

static void create_file(const char* tmp_dir)
{
    FILE* stream;
    char path[PATH_MAX];

    strlcpy(path, tmp_dir, sizeof(path));
    strlcat(path, "/myfile", sizeof(path));

    OE_TEST((stream = fopen(path, "w")));

    for (size_t i = 0; i < _nlines; i++)
        fprintf(stream, "%s\n", _lines[i]);

    fclose(stream);

    printf("Created %s\n", path);
}

static void verify_file(const char* tmp_dir)
{
    FILE* stream;
    char path[PATH_MAX];
    char buf[1024];
    size_t i;

    strlcpy(path, tmp_dir, sizeof(path));
    strlcat(path, "/myfile", sizeof(path));

    OE_TEST((stream = fopen(path, "r")));

    for (i = 0; (fgets(buf, sizeof(buf), stream)); i++)
    {
        OE_TEST(i < _nlines);

        /* Remove the trailing newline. */
        {
            char* end = buf + strlen(buf);

            if (end[-1] == '\n')
                end[-1] = '\0';
        }

        OE_TEST(strcmp(buf, _lines[i]) == 0);
    }

    OE_TEST(i == _nlines);

    fclose(stream);

    printf("Verified %s\n", path);
}

void test_corelibc(const char* tmp_dir)
{
    OE_TEST(tmp_dir != NULL);

    oe_enable_feature(OE_FEATURE_HOST_FILES);

    if (mount("/", "/", "hostfs", 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    /* Create the temporary directory. */
    OE_TEST(mkdir(tmp_dir, 0777) == 0);

    /* Create the new file. */
    create_file(tmp_dir);

    /* Read the file back and verify it. */
    verify_file(tmp_dir);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
