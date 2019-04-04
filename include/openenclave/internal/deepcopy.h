// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEEPCOPY_H
#define _OE_DEEPCOPY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#define OE_SIZEOF(TYPE, MEMBER) (sizeof(((((TYPE*)0)->MEMBER))))

struct _oe_structure;

typedef struct _oe_field
{
    size_t field_offset;
    size_t field_size;
    size_t elem_size;
    size_t count;
    size_t count_offset;
    size_t count_size;
    const struct _oe_structure* structure;
} oe_field_t;

typedef struct _oe_structure
{
    size_t struct_size;
    const oe_field_t* fields;
    size_t num_fields;
} oe_structure_t;

/* Allocate memory from flat address space. */
typedef struct _oe_flat_allocator
{
    uint8_t* data;
    size_t capacity;
    size_t offset;
} oe_flat_allocator_t;

OE_INLINE void oe_flat_allocator_init(
    oe_flat_allocator_t* a,
    void* data,
    size_t capacity)
{
    a->capacity = capacity;
    a->data = data;
    a->offset = 0;
}

void* oe_flat_alloc(size_t size, void* a);

int oe_deep_size(
    const oe_structure_t* structure,
    const void* src,
    size_t* size);

int oe_deep_copy(
    const oe_structure_t* structure,
    const void* src,
    void* dest,
    void* (*alloc)(size_t size, void* alloc_data),
    void* alloc_data);

#endif /* _OE_DEEPCOPY_H */
