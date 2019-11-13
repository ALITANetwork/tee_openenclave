// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/sgxtypes.h>
#include "../asmdefs.h"

// The following function must not be inlined and must have a frame-pointer
// so that the frame can be manipulated to stitch the ocall stack.
// This is ensured by compiling this file with -fno-omit-frame-pointer.
OE_NEVER_INLINE
int __oe_host_stack_bridge(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    oe_enclave_t* enclave)
{
    oe_host_ocall_frame_t *current, backup;

    // Fetch pointer to current frame.
    asm volatile("mov %%rbp, %0\n\t" : "=r"(current) : : "memory");

    // Back up current frame.
    backup = *current;

    // Notify the debugger to overwrite the return address of
    // the current frame with the exit frame of the enclave.
    // This will stitch the ocall stack.
    oe_notify_ocall_start(current, tcs);

    int ret = __oe_dispatch_ocall(arg1, arg2, arg1_out, arg2_out, tcs, enclave);

    // Restore the frame so that this function can return to the caller
    // correctly. Alternatively, we could use a setjmp/longjmp combination.
    *current = backup;

    return ret;
}
