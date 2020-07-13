// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PLUGIN
#define _OE_INTERNAL_SGX_PLUGIN

#include <openenclave/bits/report.h>
#include <openenclave/internal/crypto/sha.h>

OE_EXTERNC_BEGIN

typedef enum _sgx_evidence_format_type_t
{
    SGX_FORMAT_TYPE_UNKNOWN = 0,
    SGX_FORMAT_TYPE_LOCAL = 1,         // Evidence for SGX local attestation
    SGX_FORMAT_TYPE_REMOTE = 2,        // Evidence for SGX remote attestation
    SGX_FORMAT_TYPE_LEGACY_REPORT = 3, // Report for SGX remote attestation
    SGX_FORMAT_TYPE_RAW_QUOTE = 4      // Raw SGX quote
} sgx_evidence_format_type_t;

/**
 * oe_sgx_extract_claims
 *
 * Extract claims from an evidence buffer.
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] format_type The format of the evidence in report_body.
 * This is derived from format_id by the caller
 * @param[in] format_id Pointer to the evidence format ID requested.
 * @param[in] report_body Pointer to a buffer with raw SGX quote / report.
 * @param[in] report_body_size Size of the report_body buffer.
 * @param[in] sgx_endorsements Pointer to the endorsements buffer.
 * @param[in] custom_claims the data in a flat buffer to be packaged as a
 * claim of ID OE_CLAIM_CUSTOM_CLAIMS when format_type has the right value.
 * @param[in] custom_claims_size The size of the custom_claims buffer.
 * @param[out] claims_out Pointer to the address of a dynamically allocated
 * buffer holding the list of claims (including base and custom claims).
 * @param[out] claims_length_out The length of the claims_out list.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
struct _oe_sgx_endorsements_t;
oe_result_t oe_sgx_extract_claims(
    const sgx_evidence_format_type_t format_type,
    const oe_uuid_t* format_id,
    const uint8_t* report_body,
    size_t report_body_size,
    const uint8_t* custom_claims,
    size_t custom_claims_size,
    const struct _oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t** claims_out,
    size_t* claims_length_out);

/**
 * oe_sgx_hash_custom_claims
 *
 * Calculate the hash of a custom_claims buffer
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] custom_claims Custom claims in a flat buffer.
 * @param[in] custom_claims_size The number of bytes in the custom claims
 * buffer.
 * @param[out] hash_out hash of the custom claims.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_sgx_hash_custom_claims(
    const void* custom_claims,
    size_t custom_claims_size,
    OE_SHA256* hash_out);

OE_EXTERNC_END

#endif // _OE_INTENRAL_SGX_PLUGIN
