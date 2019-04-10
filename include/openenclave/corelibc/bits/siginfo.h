// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define __OE_SI_PAD_SIZE ((128 / sizeof(int)) - 4)

typedef struct
{
    int si_signo;
    int si_errno;
    int si_code;
    union {
        int __si_pad[__OE_SI_PAD_SIZE];

        /* kill() */
        struct
        {
            pid_t si_pid; /* sender's pid */
            uid_t si_uid; /* sender's uid */
        } __si_kill;

        /* POSIX.1b timers */
        struct
        {
            void* si_tid;   /* timer id */
            int si_overrun; /* overrun count */
            char __si_pad[sizeof(uid_t) - sizeof(int)];
            union oe_sigval si_sigval; /* same as below */
            int si_sys_private;        /* not to be passed to user */
        } __si_timer;

        /* POSIX.1b signals */
        struct
        {
            pid_t si_pid;    /* sender's pid */
            uint32_t si_uid; /* sender's uid */
            union oe_sigval si_sigval;
        } __si_rt;

    } __si_fields;
} __OE_SIGINFO;
