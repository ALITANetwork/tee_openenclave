// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TYPEINFO_H
#define _OE_TYPEINFO_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_pointer_field_ti oe_pointer_field_ti_t;
typedef struct _oe_struct_ti oe_struct_ti_t;
typedef struct _oe_param_ti oe_param_ti_t;
typedef struct _oe_function_ti oe_function_ti_t;

// Type flags:
#define OE_FLAG_STRUCT (1 << 0)
#define OE_FLAG_CONST (1 << 1)
#define OE_FLAG_PTR (1 << 2)
#define OE_FLAG_ARRAY (1 << 3)

// Qualifier flags:
#define OE_FLAG_ECALL (1 << 5)
#define OE_FLAG_OCALL (1 << 6)
#define OE_FLAG_IN (1 << 7)
#define OE_FLAG_OUT (1 << 8)
#define OE_FLAG_REF (1 << 9)
#define OE_FLAG_UNCHECKED (1 << 10)
#define OE_FLAG_COUNT (1 << 11)
#define OE_FLAG_STRING (1 << 12)
#define OE_FLAG_OPT (1 << 13)

struct _oe_pointer_field_ti
{
    /* flags (OE_FLAG_*) */
    uint32_t flags;

    /* Name of this field */
    const char* name;

    /* Type of field (OE_TYPE_*) */
    oe_type_t type;

    /* Type information for this structure (when type==OE_STRUCT_TYPE) */
    const oe_struct_ti_t* sti;

    /* For pointer types: the field in the struct that holds the array size */
    const char* count_field;

    /* Offset of this field within struct */
    size_t offset;

    /* Size of this type */
    size_t size;

    /* Array subscript (when type==OE_FLAG_ARRAY) */
    int32_t subscript;
};

struct _oe_struct_ti
{
    /* flags (OE_FLAG_*) */
    uint32_t flags;

    /* Name of this structure */
    const char* name;

    /* Size of this structure in bytes */
    size_t size;

    /* Pointer to array of fields */
    const oe_pointer_field_ti_t* fields;

    /* Number of fields in the array */
    uint32_t nfields;
};

oe_result_t oe_struct_eq(
    const oe_struct_ti_t* sti,
    const void* s1,
    const void* s2,
    bool* flag);

oe_result_t oe_copy_struct(
    const oe_struct_ti_t* struc_ti,
    const void* struct_in,
    void* struct_out,
    void*(alloc)(size_t size));

oe_result_t oe_clone_struct(
    const oe_struct_ti_t* struct_ti,
    const void* struct_in,
    void** struct_out,
    void*(alloc)(size_t size));

void oe_print_struct(const oe_struct_ti_t* struct_ti, const void* struct_in);

oe_result_t oe_destroy_struct(
    const oe_struct_ti_t* struct_ti,
    void* struct_ptr,
    oe_dealloc_proc_t dealloc);

oe_result_t oe_free_struct(
    const oe_struct_ti_t* struct_ti,
    void* struct_ptr,
    oe_dealloc_proc_t dealloc);

oe_result_t oe_init_arg(
    const oe_struct_ti_t* sti,
    void* strct,
    size_t index,
    bool is_ptr_ptr,
    void* arg,
    void*(alloc)(size_t size));

oe_result_t oe_clear_arg(
    const oe_struct_ti_t* sti,
    void* strct,
    size_t index,
    bool is_ptr_ptr,
    void* arg,
    oe_dealloc_proc_t dealloc);

oe_result_t oe_clear_arg_by_name(
    const oe_struct_ti_t* sti,
    void* strct,
    const char* name,
    bool is_ptr_ptr,
    void* arg,
    oe_dealloc_proc_t dealloc);

oe_result_t oe_set_arg(
    const oe_struct_ti_t* sti,
    void* strct,
    size_t index,
    bool is_ptr_ptr, /* if 'arg' is a pointer to a pointer to an object */
    void* arg,
    void*(alloc)(size_t size));

oe_result_t oe_set_arg_by_name(
    const oe_struct_ti_t* sti,
    void* strct,
    const char* name,
    bool is_ptr_ptr, /* if 'arg' is a pointer to a pointer to an object */
    void* arg,
    void*(alloc)(size_t size));

size_t oe_struct_find_field(const oe_struct_ti_t* struct_ti, const char* name);

oe_result_t oe_check_pre_constraints(
    const oe_struct_ti_t* sti,
    const void* sin);

oe_result_t oe_check_post_constraints(
    const oe_struct_ti_t* sti,
    const void* sin);

oe_result_t oe_test_struct_padding(const oe_struct_ti_t* sti, const void* sin);

oe_result_t oe_pad_struct(const oe_struct_ti_t* sti, const void* sin);

oe_result_t oe_check_struct(const oe_struct_ti_t* ti, void* strct);

OE_EXTERNC_END

#endif /* _OE_TYPEINFO_H */
