
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_SIGNAL_H
#define _OE_SIGNAL_H

#include "openenclave/internal/uid.h"

#define _SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))
typedef struct
{
    unsigned long int __val[_SIGSET_NWORDS];
} sigset_t;

typedef void (*sighandler_t)(int);
#define SIG_ERR ((sighandler_t)-1) /* Error return.  */
#define SIG_DFL ((sighandler_t)0)  /* Default action.  */
#define SIG_IGN ((sighandler_t)1)  /* Ignore signal.  */

#define SIGINT 2
#define SIGILL 4
#define SIGABRT 6
#define SIGFPE 8
#define SIGSEGV 11
#define SIGTERM 15
#define SIGHUP 1
#define SIGQUIT 3
#define SIGTRAP 5
#define SIGKILL 9
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28

#define SIGBUS 7
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGURG 23
#define SIGPOLL 29
#define SIGSYS 31

/* Archaic names for compatibility.  */
#define SIGIO SIGPOLL
#define SIGIOT SIGABRT
#define SIGCLD SIGCHLD

#define _NSIG 32

union sigval {
    int sival_int;
    void* sival_ptr;
};

typedef union sigval sigval_t;

#define __SI_MAX_SIZE 128
#define SI_PAD_SIZE ((__SI_MAX_SIZE / sizeof(int)) - 4)

typedef struct siginfo
{
    int si_signo;
    int si_errno;
    int si_code;

    union {
        int _pad[SI_PAD_SIZE];

        /* kill() */
        struct
        {
            oe_pid_t _pid; /* sender's pid */
            oe_uid_t _uid; /* sender's uid */
        } _kill;

        /* POSIX.1b timers */
        struct
        {
            void* _tid;   /* timer id */
            int _overrun; /* overrun count */
            char _pad[sizeof(oe_uid_t) - sizeof(int)];
            sigval_t _sigval; /* same as below */
            int _sys_private; /* not to be passed to user */
        } _timer;

        /* POSIX.1b signals */
        struct
        {
            oe_pid_t _pid; /* sender's pid */
            uint32_t _uid; /* sender's uid */
            sigval_t _sigval;
        } _rt;

    } _sifields;
} siginfo_t;

// Only flag supported. 3 args for the sighandler rather than 1
#define SA_SIGINFO 0x00000004

struct sigaction
{
    /* Signal handler.  */
    union {
        sighandler_t sa_handler;
        void (*sa_sigaction)(int, siginfo_t*, void*);
    } __sigaction_handler;

    /* Additional set of signals to be blocked.  */
    sigset_t sa_mask;

    /* Special flags.  */
    int sa_flags;

    /* Restore handler.  */
    void (*sa_restorer)(void); // Never used
};

sighandler_t oe_signal(int signum, sighandler_t handler);

int oe_kill(oe_pid_t pid, int signum);

int oe_sigaction(
    int sig,
    const struct sigaction* act,
    struct sigaction* oldact);

#endif
