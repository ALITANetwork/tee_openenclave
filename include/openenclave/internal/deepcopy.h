// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEEPCOPY_H
#define _OE_DEEPCOPY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#define OE_SIZEOF(TYPE, MEMBER) (sizeof(((((TYPE*)0)->MEMBER))))

struct _oe_structure;

/* This structure provides type information for a pointer field within a
 * structure.
 */
typedef struct _oe_pointer_field
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

    /* The oe_structure_t type information for this field. */
    const struct _oe_structure* structure;

} oe_pointer_field_t;

/* This structure provides type information for a structure definition.
 */
typedef struct _oe_structure
{
    size_t struct_size;
    const oe_pointer_field_t* fields;
    size_t num_fields;
} oe_structure_t;

oe_result_t oe_deep_copy(
    const oe_structure_t* structure,
    const void* src,
    void* dest,
    size_t* dest_size_in_out);

#endif /* _OE_DEEPCOPY_H */
