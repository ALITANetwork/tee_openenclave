// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file enclave.h
 *
 * This file defines the programming interface for developing enclaves.
 *
 */
#ifndef _OE_ENCLAVE_H
#define _OE_ENCLAVE_H

#ifdef _OE_HOST_H
#error "enclave.h and host.h must not be included in the same compilation unit."
#endif

#include "bits/defs.h"
#include "bits/devid.h"
#include "bits/exception.h"
#include "bits/properties.h"
#include "bits/report.h"
#include "bits/result.h"
#include "bits/types.h"

#define OE_NGROUP_MAX 256

/**
 * @cond IGNORE
 */
OE_EXTERNC_BEGIN

/**
 * @endcond
 */

/**
 * Register a new vectored exception handler.
 *
 * Call this function to add a new vectored exception handler. If successful,
 * the registered handler will be called when an exception happens inside the
 * enclave.
 *
 * @param is_first_handler The parameter indicates that the input handler should
 * be the first exception handler to be called. If it is false, the input
 * handler will be appended to the end of exception handler chain, otherwise
 * it will be added as the first handler in the exception handler chain.
 * @param vectored_handler The input vectored exception handler to register. It
 * must be a function defined in the enclave. The same handler can only be
 * registered once; a 2nd registration will fail. If the function succeeds, the
 * handler may be removed later by passing it to
 * oe_remove_vectored_exception_handler().
 *
 * @returns OE_OK successful
 * @returns OE_INVALID_PARAMETER a parameter is invalid
 * @returns OE_FAILURE failed to add handler
 */
oe_result_t oe_add_vectored_exception_handler(
    bool is_first_handler,
    oe_vectored_exception_handler_t vectored_handler);

/**
 * Remove an existing vectored exception handler.
 *
 * @param vectored_handler The pointer to a registered exception handler
 * returned from a successful oe_add_vectored_exception_handler() call.
 *
 * @returns OE_OK success
 * @returns OE_INVALID_PARAMETER a parameter is invalid
 * @returns OE_FAILURE failed to remove handler
 */
oe_result_t oe_remove_vectored_exception_handler(
    oe_vectored_exception_handler_t vectored_handler);

/**
 * Check whether the given buffer is strictly within the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly within the enclave's memory. If so, return true. If any
 * portion of the buffer lies outside the enclave's memory, return false.
 *
 * @param ptr The pointer pointer to buffer.
 * @param size The size of buffer
 *
 * @retval true The buffer is strictly within the enclave.
 * @retval false At least some part of the buffer is outside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_within_enclave(const void* ptr, size_t size);

/**
 * Check whether the given buffer is strictly outside the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly outside the enclave's memory. If so, return true. If any
 * portion of the buffer lies within the enclave's memory, return false.
 *
 * @param ptr The pointer to buffer.
 * @param size The size of buffer.
 *
 * @retval true The buffer is strictly outside the enclave.
 * @retval false At least some part of the buffer is inside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_outside_enclave(const void* ptr, size_t size);

/**
 * Allocate bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and returns the
 * address of the allocated memory. The implementation performs an OCALL to
 * the host, which calls malloc(). To free the memory, it must be passed to
 * oe_host_free().
 *
 * @param size The number of bytes to be allocated.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_malloc(size_t size);

/**
 * Reallocate bytes from the host's heap.
 *
 * This function changes the size of the memory block pointed to by **ptr**
 * on the host's heap to **size** bytes. The memory block may be moved to a
 * new location, which is returned by this function. The implementation
 * performs an OCALL to the host, which calls realloc(). To free the memory,
 * it must be passed to oe_host_free().
 *
 * @param ptr The memory block to change the size of. If NULL, this method
 * allocates **size** bytes as if oe_host_malloc was invoked. If not NULL,
 * it should be a pointer returned by a previous call to oe_host_calloc,
 * oe_host_malloc or oe_host_realloc.
 * @param size The number of bytes to be allocated. If 0, this method
 * deallocates the memory at **ptr**. If the new size is larger, the value
 * of the memory in the new allocated range is indeterminate.
 *
 * @returns The pointer to the reallocated memory or NULL if **ptr** was
 * freed by setting **size** to 0. This method also returns NULL if it was
 * unable to reallocate the memory, in which case the original **ptr**
 * remains valid and its contents are unchanged.
 *
 */
void* oe_host_realloc(void* ptr, size_t size);

/**
 * Allocate zero-filled bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and fills it
 * with zero character. It returns the address of the allocated memory. The
 * implementation performs an OCALL to the host, which calls calloc().
 * To free the memory, it must be passed to oe_host_free().
 *
 * @param nmemb The number of elements to be allocated and zero-filled.
 * @param size The size of each element.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_calloc(size_t nmemb, size_t size);

/**
 * Release allocated memory.
 *
 * This function releases memory allocated with oe_host_malloc() or
 * oe_host_calloc() by performing an OCALL where the host calls free().
 *
 * @param ptr Pointer to memory to be released or null.
 *
 */
void oe_host_free(void* ptr);

/**
 * Make a heap copy of a string.
 *
 * This function allocates memory on the host's heap, copies no more than
 * *n* bytes from the **str** parameter to that memory, and returns a pointer
 * to the newly allocated memory.
 *
 * @param str The string to be copied.
 * @param n The number of characters to be copied.
 *
 * @returns A pointer to the newly allocated string or NULL if unable to
 * allocate the storage.
 */
char* oe_host_strndup(const char* str, size_t n);

/**
 * Abort execution of the enclave.
 *
 * Mark the enclave as aborting. This blocks future enclave entry calls. The
 * enclave continues to execute until all threads exit the enclave.
 */
void oe_abort(void);

/**
 * @cond IGNORE
 */

/**
 * Called whenever an assertion fails.
 *
 * This internal function is called when the expression of the oe_assert()
 * macro evaluates to zero. For example:
 *
 *     oe_assert(x > y);
 *
 * If the expression evaluates to zero, this function is called with the
 * string representation of the expression as well as the file, the line, and
 * the function name where the macro was expanded.
 *
 * The __oe_assert_fail() function performs a host call to print a message
 * and then calls oe_abort().
 *
 * @param expr The argument of the oe_assert() macro.
 * @param file The name of the file where oe_assert() was invoked.
 * @param line The line number where oe_assert() was invoked.
 * @param func The name of the function that invoked oe_assert().
 *
 */
void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);
/**
 * @endcond
 */

/**
 * Evaluates assertion.
 * If EXPR evaulates to zero, this function is called with the
 * string representation of the expression as well as the file, the line, and
 * the function name where the macro was expanded.
 */
#ifndef NDEBUG
#define oe_assert(EXPR)                                                \
    do                                                                 \
    {                                                                  \
        if (!(EXPR))                                                   \
            __oe_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define oe_assert(EXPR)
#endif

#if (OE_API_VERSION < 2)
#define oe_get_report oe_get_report_v1
#else
#define oe_get_report oe_get_report_v2
#endif

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **report_data** parameter.
 *
 * If the *report_buffer* is NULL or *report_size* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_report_v2() instead.
 *
 * @param flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param report_data The report data that will be included in the report.
 * @param report_data_size The size of the **report_data** in bytes.
 * @param opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param opt_params_size The size of the **opt_params** buffer.
 * @param report_buffer The buffer to where the resulting report will be copied.
 * @param report_buffer_size The size of the **report** buffer. This is set to
 * the
 * required size of the report buffer on return.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **report_buffer** buffer is NULL or too
 * small.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v1(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size);

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **report_data** parameter.
 *
 * @param[in] flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param[in] report_data The report data that will be included in the report.
 * @param[in] report_data_size The size of the **report_data** in bytes.
 * @param[in] opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param[in] opt_params_size The size of the **opt_params** buffer.
 * @param[out] report_buffer This points to the resulting report upon success.
 * @param[out] report_buffer_size This is set to the
 * size of the report buffer on success.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

/**
 * Frees a report buffer obtained from oe_get_report.
 *
 * @param[in] report_buffer The report buffer to free.
 */
void oe_free_report(uint8_t* report_buffer);

#if (OE_API_VERSION < 2)
#define oe_get_target_info oe_get_target_info_v1
#else
#define oe_get_target_info oe_get_target_info_v2
#endif

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * If the *target_info_buffer* is NULL or the *target_info_size* parameter is
 * too small, this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_target_info_v2() instead.
 *
 * @param report The report returned by **oe_get_report**.
 * @param report_size The size of **report** in bytes.
 * @param target_info_buffer The buffer to where the platform specific data
 * will be placed.
 * @param target_info_size The size of **target_info_buffer**. This is set to
 * the required size of **target_info_buffer** on return.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL **target_info_buffer** is NULL or too small.
 *
 */
oe_result_t oe_get_target_info_v1(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size);

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * @param[in] report The report returned by **oe_get_report**.
 * @param[in] report_size The size of **report** in bytes.
 * @param[out] target_info_buffer This points to the platform specific data
 * upon success.
 * @param[out] target_info_size This is set to
 * the size of **target_info_buffer** on success.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size);

/**
 * Frees target info obtained from oe_get_target_info.
 *
 * @param[in] target_info The platform specific data to free.
 *
 */
void oe_free_target_info(void* target_info);

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report The **oe_report_t** structure to populate with the
 * report
 * properties in a standard format. The *parsed_report* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Verify the integrity of the report and its signature.
 *
 * This function verifies that the report signature is valid. If the report is
 * local, it verifies that it is correctly signed by the enclave
 * platform. If the report is remote, it verifies that the signing authority is
 * rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

#if (OE_API_VERSION < 2)
#define oe_get_seal_key_by_policy oe_get_seal_key_by_policy_v1
#else
#define oe_get_seal_key_by_policy oe_get_seal_key_by_policy_v2
#endif

/**
 * Get a symmetric encryption key derived from the specified policy and coupled
 * to the enclave platform.
 *
 * @deprecated This function is deprecated. Use oe_get_seal_key_by_policy_v2()
 instead.
 *
 * @param seal_policy The policy for the identity properties used to derive the
 * seal key.
 * @param key_buffer The buffer to write the resulting seal key to.
 * @param key_buffer_size The size of the **key_buffer** buffer. If this is too
 * small, this function sets it to the required size and returns
 * OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
 * to key_buffer is set to it.
 * @param key_info Optional buffer for the enclave-specific key information
 which
 * can be used to retrieve the same key later, on a newer security version.
 * @param key_info_size The size of the **key_info** buffer. If this is too
 small,
 * this function sets it to the required size and returns OE_BUFFER_TOO_SMALL.
 * When this function success, the number of bytes written to key_info is set to
 * it.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **key_buffer** or **key_info** buffer is too
 * small.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_get_seal_key_by_policy_v1(
    oe_seal_policy_t seal_policy,
    uint8_t* key_buffer,
    size_t* key_buffer_size,
    uint8_t* key_info,
    size_t* key_info_size);

/**
 * Get a symmetric encryption key derived from the specified policy and coupled
 * to the enclave platform.
 *
 * @param[in] seal_policy The policy for the identity properties used to derive
 * the
 * seal key.
 * @param[out] key_buffer This contains the resulting seal key upon success.
 * Freed by calling oe_free_key().
 * @param[out] key_buffer_size This contains the size of the **key_buffer**
 * buffer upon success.
 * @param[out] key_info If non-NULL, then on success this points to the
 * enclave-specific key information which
 * can be used to retrieve the same key later, on a newer security version.
 * Freed by calling oe_free_key().
 * @param[out] key_info_size On success, this is the size of the **key_info**
 * buffer.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_UNEXPECTED An unexpected error happened.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_seal_key_by_policy_v2(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

#if (OE_API_VERSION < 2)
#define oe_get_seal_key oe_get_seal_key_v1
#else
#define oe_get_seal_key oe_get_seal_key_v2
#endif

/**
 * Get a symmetric encryption key from the enclave platform using existing key
 * information.
 *
 * @deprecated This function is deprecated. Use oe_get_seal_key_v2() instead.
 *
 * @param key_info The enclave-specific key information to derive the seal key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer The buffer to write the resulting seal key to. It will not
 * be changed if this function fails.
 * @param key_buffer_size The size of the **key_buffer** buffer. If this is too
 * small, this function sets it to the required size and returns
 * OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
 * to key_buffer is set to it.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **key_buffer** buffer is too small.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 */
oe_result_t oe_get_seal_key_v1(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t* key_buffer,
    size_t* key_buffer_size);

/**
 * Returns a public key that is associated with the identity of the enclave
 * and the specified policy.
 *
 * @param seal_policy The policy for the identity properties used to derive
 * the key.
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested public key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 * @param key_info Optional pointer to a buffer for the enclave-specific key
 * information which can be used to retrieve the same key later on a newer
 * security version.
 * @param key_info_size On success, this contains the size of key_info.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY There is no memory available.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Returns a public key that is associated with the identity of the enclave.
 *
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_info The enclave-specific key information to derive the key.
 * @param key_info_size The size of the key_info buffer.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested public key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN The platform specific data has an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN The platform specific data has an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME The platform specific data has an invalid KEYNAME.
 */
oe_result_t oe_get_public_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Returns a private key that is associated with the identity of the enclave
 * and the specified policy.
 *
 * @param seal_policy The policy for the identity properties used to derive
 * the asymmetric key.
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested private key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 * @param key_info Optional pointer to a buffer for the enclave-specific key
 * information which can be used to retrieve the same key later on a newer
 * security version.
 * @param key_info_size On success, this contains the size of key_info.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY There is no memory available.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Returns a private key that is associated with the identity of the enclave.
 *
 * @param key_params The parameters for the asymmetric key derivation.
 * @param key_info The enclave-specific key information to derive the key.
 * @param key_info_size The size of the key_info buffer.
 * @param key_buffer A pointer to the buffer that on success contains the
 * requested private key.
 * @param key_buffer_size On success, this contains size of key_buffer.
 *
 * @retval OE_OK The key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN The platform specific data has an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN The platform specific data has an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME The platform specific data has an invalid KEYNAME.
 */
oe_result_t oe_get_private_key(
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Frees the given key and/or key info. Before freeing, this function will
 * zero out the key buffers to avoid leaking any confidential data..
 *
 * @param key_buffer If not NULL, the key buffer to free.
 * @param key_buffer_size The size of key_buffer.
 * @param key_info If not NULL, the key info to free.
 * @param key_info_size The size of key_info.
 */
void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size);

/**
 * Get a symmetric encryption key from the enclave platform using existing key
 * information.
 *
 * @param key_info The enclave-specific key information to derive the seal key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer Upon success, this points to the resulting seal key, which
 * should be freed with oe_free_key().
 * @param key_buffer_size Upon success, this contains the size of the
 * **key_buffer** buffer, which should be freed with oe_free_key().
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Frees a key and/or key info.
 *
 * @param key_buffer If non-NULL, the key buffer to free.
 * @param key_info If non-NULL, the key info buffer to free.
 */
void oe_free_seal_key(uint8_t* key_buffer, uint8_t* key_info);

/**
 * Obtains the enclave handle.
 *
 * This function returns the enclave handle for the current enclave. The
 * host obtains this handle by calling **oe_create_enclave()**, which
 * passes the enclave handle to the enclave during initialization. The
 * handle is an address inside the host address space.
 *
 * @returns the enclave handle.
 */
oe_enclave_t* oe_get_enclave(void);

/**
 * Generate a sequence of random bytes.
 *
 * This function generates a sequence of random bytes.
 *
 * @param data the buffer that will be filled with random bytes
 * @param size the size of the buffer
 *
 * @return OE_OK on success
 */
oe_result_t oe_random(void* data, size_t size);

typedef enum _oe_feature
{
    OE_FEATURE_HOST_FILES,
    OE_FEATURE_HOST_SOCKETS,
    OE_FEATURE_POLLING,
    OE_FEATURE_HOST_RESOLVER,
    __OE_FEATURE_MAX,
} oe_feature_t;

/**
 * Enable the enclave feature given by the feature parameter.
 *
 * This function enables the given enclave feature. By default, all features
 * that affect the enclave's security characteristics are disabled. Calling
 * this function effectively opts into a given feature. For example,
 * **OE_FEATURE_HOST_FILES** allows the enclave to access files on the
 * host file system. Always use this function with care as it modifies the
 * security policy of the enclave in some way.
 *
 * @param feature enable this feature.
 *
 * @return OE_OK on success
 */
oe_result_t oe_enable_feature(oe_feature_t feature);

/**
 * oe_gen_cert_for_tls.
 *
 * This function generates a self-signed certificate with an embedded quote from
 * the underlying enclave.
 *
 * @param issuer_key: a private key used to sign this certificate
 * @param issuer_key_size The size of the issuer_key buffer.
 * @param subject_key: a public key used to in the certificate
 * @param subject_key_size The size of the subject_key buffer.
 *
 * @param output_cert: a pointer to buffer pointer, where the buffer is
 * allocated by a client
 * @param output_cert_size: size of the buffer above.
 *
 * @return OE_OK on success
 */
oe_result_t oe_gen_cert_for_tls(
    uint8_t* issuer_key,
    size_t issuer_key_size,
    uint8_t* subject_key,
    size_t subject_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size);
/**
 * Free the given cert
 * @param cert If not NULL, the buffer to free.
 */
void oe_free_x509cert_for_TLS(uint8_t* cert);

/**
 * oe_verify_tls_cert
 *
 * This function preform a custom validation on the input certificate. This
 * validation includes exacting a quote extension from the certificate before
 * performing a quote validation on it. An optional enclave_identity_callback
 * could be passed in for a calling client to further validate the identity of
 * the enclave creating the quote.
 * @retval OE_OK on a successful validation
 * @retval appropriate error code when failed.
 */
typedef oe_result_t (
    *oe_enclave_identity_verify_callback_t)(oe_identity_t* identity, void* arg);
oe_result_t oe_verify_tls_cert(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_enclave_identity_verify_callback_t enclave_identity_callback,
    void* arg);

OE_EXTERNC_END

#endif /* _OE_ENCLAVE_H */
