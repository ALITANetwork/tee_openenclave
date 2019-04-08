// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/syscall.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "mbed_t.h"

int main(int argc, const char* argv[]);
struct mbed_args gmbed_args;

void _exit(int status)
{
    ocall_exit(status);
    abort();
}

void _Exit(int status)
{
    _exit(status);
    abort();
}

void exit(int status)
{
    _exit(status);
    abort();
}

char* oe_host_strdup(const char* str)
{
    s ize_t n = strlen(str);
    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
        memcpy(dup, str, n + 1);

    return dup;
}
void test_checker(char* str)
{
    int i;
    char* token[6];
    if ((strncmp(str, "PASSED (", 8) == 0) && (strlen(str) >= 32))
    {
        token[0] = strtok(str, " ");
        for (i = 1; i < 6; i++)
        {
            token[i] = strtok(NULL, " ");
        }
        gmbed_args.total = atoi(token[3]);
        // Since the first character of subtoken is '('  avoiding it
        gmbed_args.skipped = atoi((token[5] + 1));
    }
}

int test(
    const char* in_testname,
    char out_testname[STRLEN],
    struct mbed_args* args)
{
    int return_value = -1;
    printf("RUNNING: %s\n", __TEST__);

    // verbose option is enabled as some of the functionality in helper.function
    // such as redirect output, restore output is trying to assign values to
    // stdout which in turn causes segmentation fault.  To avoid this we enabled
    // verbose options such that those function calls will be suppressed.
    if (0 == strcmp(__TEST__, "selftest"))
    {
        // selftest treats the verbose flag "-v" as an invalid test suite name,
        // so drop all args when invoking the test, which will execute all
        // selftests
        static const char* noargs[2] = {NULL};
        return_value = main(1, noargs);
    }
    else
    {
        static const char* argv[] = {"test", "-v", "NULL"};
        static int argc = sizeof(argv) / sizeof(argv[0]);
        argv[2] = in_testname;
        return_value = main(argc, argv);
        args->skipped = gmbed_args.skipped;
        args->total = gmbed_args.total;
    }
    strncpy(out_testname, __TEST__, STRLEN);
    out_testname[STRLEN - 1] = '\0';

    return return_value;
}

/*
 **==============================================================================
 **
 ** oe_handle_verify_report()
 ** oe_handle_get_public_key_by_policy()
 ** oe_handle_get_public_key()
 **
 **     Since liboeenclave is not linked, we must define a version of these
 **     functions here (since liboecore depends on it). This version asserts
 **     and aborts().
 **
 **==============================================================================
 */

void oe_handle_verify_report(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);
    OE_UNUSED(arg_out);
    assert("oe_handle_verify_report()" == NULL);
    abort();
}

void oe_handle_get_public_key_by_policy(uint64_t arg_in)
{
    OE_UNUSED(arg_in);
    assert("oe_handle_get_public_key_by_policy()" == NULL);
    abort();
}

void oe_handle_get_public_key(uint64_t arg_in)
{
    OE_UNUSED(arg_in);
    assert("oe_handle_get_public_key()" == NULL);
    abort();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    512,  /* HeapPageCount */
    512,  /* StackPageCount */
    2);   /* TCSCount */
