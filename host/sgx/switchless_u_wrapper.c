// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>

/* Override oe_call_enclave_function() with _call_switchless_enclave_function().
 */
#define oe_call_enclave_function _call_switchless_enclave_function

/* Obscure the generated creation function by renaming it. */
#define oe_create_switchless_enclave __unused_oe_create_switchless_enclave

/* The ocall edge routines will use this function to route switchless ecalls. */
static oe_result_t _call_switchless_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_enclave_function_by_table_id(
        enclave,
        OE_SWITCHLESS_ECALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

/* Include the oeedger8r generated C file. The macros defined above customize
 * the generated code for internal use. */
#include "switchless_u.c"

/* Registers the switchless OCALL function table. */
oe_result_t oe_register_switchless_ocall_function_table(void)
{
    const uint64_t table_id = OE_SWITCHLESS_OCALL_FUNCTION_TABLE_ID;
    const oe_ocall_func_t* ocalls = __switchless_ocall_function_table;
    const size_t num_ocalls = OE_COUNTOF(__switchless_ocall_function_table);

    return oe_register_ocall_function_table(table_id, ocalls, num_ocalls);
}
