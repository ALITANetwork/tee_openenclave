// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/signal.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/print.h>
#include "oe_t.h"
// clang-format on

// Poll uses much of the infrastructure from epoll.

static void _handle_ignore(int signum);

static struct sigaction _actions[_NSIG] = {{{0}}};
static sighandler_t _default_actions[_NSIG] = {
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore};

static void _handle_ignore(int signum)
{
    (void)signum;
}

static void _handle_continue(int signum)
{
    (void)signum;
}

static void _handle_terminate(int signum)
{
    (void)signum;
}

static void _handle_error(int signum)
{
    (void)signum;
}

int oe_kill(oe_pid_t pid, int signum)
{
    int retval = -1;
    oe_errno = 0;

    if (oe_signal_kill(&retval, (int)pid, signum, &oe_errno) != OE_OK)
    {
        goto done;
    }

    retval = 0;

done:
    return retval;
}

int oe_sigaction(
    int signum,
    const struct sigaction* act,
    struct sigaction* oldact)
{
    int retval = -1;

    if (signum >= _NSIG)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oldact)
    {
        *oldact = _actions[signum];
    }

    if (act)
    {
        _actions[signum] = *act;
    }

    retval = 0;
done:
    return retval;
}

sighandler_t oe_signal(int signum, sighandler_t handler)
{
    sighandler_t retval = SIG_ERR;

    if (signum >= _NSIG)
    {
        oe_errno = EINVAL;
        goto done;
    }

    _actions[signum].__sigaction_handler.sa_handler = handler;

done:
    return retval;
}

int oe_signal_notify(int signum)
{
    int ret = -1;

    if (signum >= _NSIG)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_actions[signum].sa_flags & SA_SIGINFO)
    {
        // Get some siginfo and populate: This only lasts to the end of the call

        siginfo_t info = {0};
        info.si_signo = signum;
        info.si_errno = oe_errno;
        info.si_code = 0;
        info._sifields._kill._pid = oe_getpid();
        info._sifields._kill._uid = oe_getuid();

        /* we don't do a ucontext, and only a minimal info */
        (*_actions[signum].__sigaction_handler.sa_sigaction)(
            signum, &info, NULL);
        ret = 0;
    }
    else
    {
        switch ((int)(_actions[signum].__sigaction_handler.sa_handler))
        {
            case (int)SIG_DFL:
                (*_default_actions[signum])(signum);
                break;
            case (int)SIG_ERR:
                _handle_error(signum);
                break;
            case (int)SIG_IGN:
                _handle_ignore(signum);
                break;

            default:
                (*_actions[signum].__sigaction_handler.sa_handler)(signum);
                break;
        }
        ret = 0;
    }

done:
    return ret;
}
