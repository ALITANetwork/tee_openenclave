// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/deepcopy.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "deepcopy_t.h"

/*
**==============================================================================
**
** Structure definitions:
**
**==============================================================================
*/

struct widget
{
    int value;
    const char* str;
};

struct gadget
{
    int value;
    struct widget* widgets;
    size_t num_widgets;
};

/*
**==============================================================================
**
** Hand-coded type information.
**
**==============================================================================
*/

// clang-format off

static oe_field_type_info_t _widget_ftis[] =
{
    {
        .field_offset = OE_OFFSETOF(struct widget, str),
        .field_size = OE_SIZEOF(struct widget, str),
        .elem_size = sizeof(char),
        .count_offset = OE_SIZE_MAX,
        .count_value = OE_SIZE_MAX,
    },
};

static oe_struct_type_info_t _widget_struct =
{
    sizeof(struct widget),
    _widget_ftis,
    OE_COUNTOF(_widget_ftis),
};

static oe_field_type_info_t _gadget_ftis[] =
{
    {
        .field_offset = OE_OFFSETOF(struct gadget, widgets),
         .field_size = OE_SIZEOF(struct gadget, widgets),
         .elem_size = sizeof(struct widget),
         .count_offset = OE_OFFSETOF(struct gadget, num_widgets),
         .count_value = OE_SIZEOF(struct gadget, num_widgets),
         .sti = &_widget_struct
     },
};

static oe_struct_type_info_t _gadget_fti =
{
    sizeof(struct gadget),
    _gadget_ftis,
    OE_COUNTOF(_gadget_ftis),
};

// clang-format on

/*
**==============================================================================
**
** Define some structures.
**
**==============================================================================
*/

static struct widget _w[] = {
    {
        .value = 1,
        .str = "red",
    },
    {
        .value = 2,
        .str = "green",
    },
    {
        .value = 3,
        .str = "blue",
    },
};

static struct gadget _g = {
    .value = 1000,
    .widgets = _w,
    .num_widgets = OE_COUNTOF(_w),
};

/*
**==============================================================================
**
** test_deepcopy()
**
**==============================================================================
*/

int test_deepcopy(void)
{
    oe_struct_type_info_t* sti = &_gadget_fti;
    struct gadget* g;
    size_t size = 0;

    /* Determine the size requirments for copying the gadget. */
    OE_TEST(oe_deep_copy(sti, &_g, NULL, &size) == OE_BUFFER_TOO_SMALL);

    /* Initialize a flat allocator with stack space. */
    OE_TEST((g = calloc(1, size)));

    /* Peform a deep copy of the gadget. */
    OE_TEST(oe_deep_copy(sti, &_g, g, &size) == OE_OK);

    OE_TEST(_g.value == g->value);
    OE_TEST(_g.num_widgets == g->num_widgets);
    OE_TEST(g->widgets);

    for (size_t i = 0; i < g->num_widgets; i++)
    {
        struct widget* w = &g->widgets[i];

        switch (i)
        {
            case 0:
            {
                OE_TEST(w->value == 1);
                OE_TEST(strcmp(w->str, "red") == 0);
                break;
            }
            case 1:
            {
                OE_TEST(w->value == 2);
                OE_TEST(strcmp(w->str, "green") == 0);
                break;
            }
            case 2:
            {
                OE_TEST(w->value == 3);
                OE_TEST(strcmp(w->str, "blue") == 0);
                break;
            }
        }
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
