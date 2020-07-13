// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common/sgx/quote.h"
#include "core_u.h"
#include "platform_u.h"
#include "quote.h"

#include "sgxquoteprovider.h"

#if !defined(OE_USE_BUILTIN_EDL)
/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_get_report_v2_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);
oe_result_t _oe_verify_local_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);
oe_result_t _oe_verify_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const void* report,
    size_t report_size);

/**
 * Make the following ECALLs weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementations. If the user opts into the EDL,
 * the implementations (which are strong) in the oeedger8r-generated code will
 * be used. This behavior is guaranteed by the linker; i.e., the linker will
 * pick the symbols defined in the object before those in the library.
 */
oe_result_t _oe_get_report_v2_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    OE_UNUSED(enclave);
    OE_UNUSED(flags);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(report_buffer);
    OE_UNUSED(report_buffer_size);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_get_report_v2_ecall, oe_get_report_v2_ecall);

oe_result_t _oe_verify_local_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    OE_UNUSED(enclave);
    OE_UNUSED(report);
    OE_UNUSED(report_size);
    OE_UNUSED(parsed_report);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_verify_local_report_ecall, oe_verify_local_report_ecall);

oe_result_t _oe_verify_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const void* report,
    size_t report_size)
{
    OE_UNUSED(enclave);
    OE_UNUSED(report);
    OE_UNUSED(report_size);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_verify_report_ecall, oe_verify_report_ecall);

#endif

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

oe_result_t oe_get_report_v2(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report = NULL;
    size_t report_size = 0;

    if (!enclave || !report_buffer || !report_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_report_v2_ecall(
        enclave,
        &result,
        flags,
        opt_params,
        opt_params_size,
        &report,
        &report_size));
    OE_CHECK(result);

    *report_buffer = report;
    *report_buffer_size = report_size;
    report = NULL;

    result = OE_OK;

done:
    if (report)
        oe_free_report(report);

    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "SGX remote attestation is not enabled. To enable, please add\n\n"
            "from \"openenclave/edl/sgx/attestation.edl\" import *;\n\n"
            "in the edl file.\n");

    return result;
}

void oe_free_report(uint8_t* report_buffer)
{
    free(report_buffer);
}

// Host version, supports ECDSA remote attestation natively.
// for SGX local attestation, it makes ecall to the enclave.
oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_verifier_t* verifier = NULL;

    if (!report || !report_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        const oe_uuid_t* uuid = &_ecdsa_uuid;

        OE_UNUSED(enclave);

        oe_verifier_initialize();

        OE_CHECK(oe_find_verifier_plugin(uuid, &verifier));

        OE_CHECK(verifier->verify_report(
            verifier, report, report_size, parsed_report));

        result = OE_OK;
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        if (!enclave)
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_CHECK(oe_verify_local_report_ecall(
            enclave, &result, report, report_size, parsed_report));
        OE_CHECK(result);
    }
    else
        OE_RAISE(OE_UNSUPPORTED);

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING("oe_verify_local_report_ecall is not supported. To "
                         "enable, please add\n\n"
                         "from \"openenclave/edl/sgx/attestation.edl\" import "
                         "oe_verify_local_report_ecall;\n\n"
                         "in the edl file.\n");

    return result;
}

oe_result_t oe_verify_report_internal(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // Intialize the quote provider if we want to verify a remote quote.
        // Note that we don't have the OE_LINK_SGX_DCAP_QL guard here since we
        // don't need the sgx libraries to verify the quote. All we need is the
        // quote provider.
        OE_CHECK(oe_initialize_quote_provider());

        // Quote attestation can be done entirely on the host side.
        OE_CHECK(oe_verify_sgx_quote(
            header->report, header->report_size, NULL, 0, NULL));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        oe_result_t retval;

        if (enclave == NULL)
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_CHECK(oe_verify_report_ecall(enclave, &retval, report, report_size));
        OE_CHECK(retval);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Optionally return parsed report.
    if (parsed_report != NULL)
        OE_CHECK(oe_parse_report(report, report_size, parsed_report));

    result = OE_OK;
done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING("oe_verify_report_ecall is not supported. To "
                         "enable, please add\n\n"
                         "from \"openenclave/edl/attestation.edl\" import "
                         "oe_verify_report_ecall;\n\n"
                         "in the edl file.\n");

    return result;
}
