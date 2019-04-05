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

typedef struct _widget
{
    int value;
    const char* str;
} widget_t;

typedef struct _gadget
{
    int value;
    widget_t* widgets;
    size_t num_widgets;
} gadget_t;

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
    OE_FTI_STRING(widget_t, str),
};

static oe_struct_type_info_t _widget_sti =
{
    sizeof(widget_t),
    _widget_ftis,
    OE_COUNTOF(_widget_ftis),
};

static oe_field_type_info_t _gadget_ftis[] =
{
    OE_FTI_STRUCTS(gadget_t, widgets, widget_t, num_widgets, &_widget_sti)
};

static oe_struct_type_info_t _gadget_fti =
{
    sizeof(gadget_t),
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

static widget_t _w[] = {
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

static gadget_t _g = {
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
    gadget_t* g;
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
        widget_t* w = &g->widgets[i];

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
