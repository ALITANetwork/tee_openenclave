// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/internal/deepcopy.h>

static __inline__ uint64_t _align(uint64_t x)
{
    const uint64_t m = 16;
    return (x + m - 1) / m * m;
}

typedef struct _allocator
{
    uint8_t* data;
    size_t capacity;
    size_t offset;
} allocator_t;

static void _allocator_init(allocator_t* a, void* data, size_t capacity)
{
    a->capacity = capacity;
    a->data = data;
    a->offset = 0;
}

static void* _alloc(size_t size, void* a_)
{
    allocator_t* a = (allocator_t*)a_;
    void* ptr;

    if (!a)
        return NULL;

    size = _align(size);

    if (size > (a->capacity - a->offset))
        return NULL;

    ptr = a->data + a->offset;
    a->offset += size;

    return ptr;
}

static int _compute_count(
    const oe_structure_t* structure,
    const void* struct_ptr,
    const oe_pointer_field_t* field,
    const void* field_ptr,
    size_t* count_out)
{
    int ret = -1;
    size_t count = 0;

    *count_out = 0;

    if (field->count_offset == OE_SIZE_MAX)
    {
        if (field->count_value == OE_SIZE_MAX)
        {
            const char* str;

            if (field->elem_size != sizeof(char))
                goto done;

            if ((str = *((const char**)field_ptr)))
                count = oe_strlen(str) + 1;
        }
        else
        {
            count = field->count_value;
        }
    }
    else
    {
        const uint8_t* p = (const uint8_t*)struct_ptr + field->count_offset;

        /* Handle case where count is given by another field. */

        if (field->count_offset + field->count_value > structure->struct_size)
            goto done;

        switch (field->count_value)
        {
            case sizeof(uint8_t):
            {
                count = *((const uint8_t*)p);
                break;
            }
            case sizeof(uint16_t):
            {
                count = *((const uint16_t*)p);
                break;
            }
            case sizeof(uint32_t):
            {
                count = *((const uint32_t*)p);
                break;
            }
            case sizeof(uint64_t):
            {
                count = *((const uint64_t*)p);
                break;
            }
            default:
            {
                goto done;
            }
        }
    }

    if (count == 0)
        goto done;

    *count_out = count;

    ret = 0;

done:
    return ret;
}

static int _deep_copy(
    const oe_structure_t* structure,
    const void* src,
    void* dest,
    void* (*alloc)(size_t size, void* alloc_data),
    void* alloc_data)
{
    int ret = -1;

    if (!structure || !src || !dest || !alloc)
        goto done;

    /* Initialize the destination memory. */
    memset(dest, 0, structure->struct_size);
    memcpy(dest, src, structure->struct_size);

    for (size_t i = 0; i < structure->num_fields; i++)
    {
        const oe_pointer_field_t* f = &structure->fields[i];
        const uint8_t* src_field = (const uint8_t*)src + f->field_offset;
        uint8_t* dest_field = (uint8_t*)dest + f->field_offset;
        size_t count;

        /* Verify that field is within structure boundaries. */
        if (f->field_offset + f->field_size > structure->struct_size)
            goto done;

        /* Skip over null pointer fields. */
        if (!*(void**)src_field)
            continue;

        /* Determine the count (the number of elements). */
        if (_compute_count(structure, src, f, src_field, &count) != 0)
            goto done;

        /* Copy this array field. */
        {
            uint8_t* data;
            size_t size = count * f->elem_size;

            /* Allocate memory for this array. */
            if (!(data = (*alloc)(size, alloc_data)))
                goto done;

            /* Assign the array field in the destination structure. */
            *((void**)dest_field) = data;

            const uint8_t* src_ptr = *((const uint8_t**)src_field);
            uint8_t* dest_ptr = *((uint8_t**)dest_field);

            /* Copy each element of this array. */
            for (size_t i = 0; i < count; i++)
            {
                if (f->structure)
                {
                    if (_deep_copy(
                            f->structure,
                            src_ptr,
                            dest_ptr,
                            alloc,
                            alloc_data) != 0)
                    {
                        goto done;
                    }
                }
                else
                {
                    memcpy(dest_ptr, src_ptr, f->elem_size);
                }

                src_ptr += f->elem_size;
                dest_ptr += f->elem_size;
            }
        }
    }

    ret = 0;

done:
    return ret;
}

static int _deep_size(
    const oe_structure_t* structure,
    const void* src,
    size_t* size)
{
    int ret = -1;

    if (!structure || !src || !size)
        goto done;

    *size = _align(structure->struct_size);

    for (size_t i = 0; i < structure->num_fields; i++)
    {
        const oe_pointer_field_t* f = &structure->fields[i];
        const uint8_t* src_field = (const uint8_t*)src + f->field_offset;
        size_t count;

        /* Verify that field is within structure boundaries. */
        if (f->field_offset + f->field_size > structure->struct_size)
            goto done;

        /* Skip over null pointer fields. */
        if (!*(void**)src_field)
            continue;

        /* Determine the count (the number of elements). */
        if (_compute_count(structure, src, f, src_field, &count) != 0)
            goto done;

        /* Determine size of this array field and its descendents. */
        {
            *size += _align(count * f->elem_size);

            const uint8_t* src_ptr = *((const uint8_t**)src_field);

            /* Copy each element of this array. */
            for (size_t i = 0; i < count; i++)
            {
                if (f->structure)
                {
                    size_t tmp_size;

                    if (_deep_size(f->structure, src_ptr, &tmp_size) != 0)
                        goto done;

                    *size += _align(tmp_size);
                }

                src_ptr += f->elem_size;
            }
        }
    }

    ret = 0;

done:
    return ret;
}

oe_result_t oe_deep_copy(
    const oe_structure_t* structure,
    const void* src,
    void* dest,
    size_t* dest_size_in_out)
{
    oe_result_t result = OE_OK;
    size_t size;

    (void)dest;

    /* Check required parameters. */
    if (!structure || !src || !dest_size_in_out)
    {
        result = OE_UNEXPECTED;
        goto done;
    }

    /* Determine whether buffer is big enough. */
    {
        if (_deep_size(structure, src, &size) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        if (size > *dest_size_in_out)
        {
            *dest_size_in_out = size;
            result = OE_BUFFER_TOO_SMALL;
            goto done;
        }

        *dest_size_in_out = size;
    }

    /* Perform the deep copy. */
    if (dest)
    {
        allocator_t a;

        _allocator_init(&a, dest, size);

        a.offset = structure->struct_size;

        if (_deep_copy(structure, src, dest, _alloc, &a) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        *dest_size_in_out = a.offset;
    }

    result = OE_OK;

done:
    return result;
}
