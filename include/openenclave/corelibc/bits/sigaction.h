// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_SIGACTION
{
    /* Signal handler.  */
    union {
        oe_sighandler_t sa_handler;
        void (*sa_sigaction)(int, oe_siginfo_t*, void*);
    } __sigaction_handler;

    /* Additional set of signals to be blocked.  */
    oe_sigset_t sa_mask;

    /* Special flags.  */
    int sa_flags;

    /* Restore handler.  */
    void (*sa_restorer)(void); // Never used
};
