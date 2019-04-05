// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEEPCOPY_H
#define _OE_DEEPCOPY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#define OE_SIZEOF(TYPE, MEMBER) (sizeof(((((TYPE*)0)->MEMBER))))

struct _oe_struct_type_info;

/* This structure provides type information for a pointer field within a
 * structure.
 */
typedef struct _oe_field_type_info
{
    /* The byte offset of this field within the structure. */
    size_t field_offset;

    /* The size of this field within the structure. */
    size_t field_size;

    /* This size of one element */
    size_t elem_size;

    /* If count_offset == SIZE_MAX:
     *     count_value contains the count.
     * Else:
     *     count_offset is the offset of the integer field containing the count.
     */
    size_t count_offset;

    /* If count_offset == SIZE_MAX:
     *     count_value contains the count. If this count is SIZE_MAX then
     *     the field is a zero-terminated string.
     * Else:
     *     count_value is the size of the integer field containing the count.
     */
    size_t count_value;

    /* The strut type information for this field. */
    const struct _oe_struct_type_info* sti;

} oe_field_type_info_t;

/* This structure provides type information for a structure definition.
 */
typedef struct _oe_struct_type_info
{
    size_t struct_size;
    const oe_field_type_info_t* fields;
    size_t num_fields;
} oe_struct_type_info_t;

/**
 * Perform a deep structure copy.
 *
 * This function performs a deep stucture copy from **src** to **dest**. The
 * destination must be big enough to hold the base structure plus any reachable
 * memory objects (dynamic strings, dynamic arrays, and pointers to structs).
 * To determine the required destination size, call this function with **dest**
 * set to null **dest_size_in_out** set to zero.
 *
 * Note: this function does not handle cycles.
 *
 * @param sti the structure type information of **src**.
 * @param src the source structure that will be deep copied.
 * @param dest the destination structure that will contain the result (may be
 *        null to determine size requirements).
 * @param dest_size_in_out size **dest** buffer on input. The required size
 *        on output.
 *
 * @return OE_OK success
 * @return OE_FAILURE the operation failed.
 * @return OE_BUFFER_TOO_SMALL the **dest** buffer is tool small and
 *         **dest_size_in_out** contain the required size.
 *
 */
oe_result_t oe_deep_copy(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest,
    size_t* dest_size_in_out);

#endif /* _OE_DEEPCOPY_H */
