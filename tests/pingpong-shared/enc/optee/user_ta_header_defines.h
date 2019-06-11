/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define TA_UUID                                            \
    { /* e229cc0f-3199-4ad3-91a7-47906fcbcc59 */           \
        0xe229cc0f, 0x3199, 0x4ad3,                        \
        {                                                  \
            0x91, 0xa7, 0x47, 0x90, 0x6f, 0xcb, 0xcc, 0x59 \
        }                                                  \
    }

#define TA_FLAGS (TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (12 * 1024)      /* 12 KB */
#define TA_DATA_SIZE (1 * 1024 * 1024) /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES                              \
    {"gp.ta.description",                                         \
     USER_TA_PROP_TYPE_STRING,                                    \
     "pingpong shared test TA"},                                  \
    {                                                             \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t) \
        {                                                         \
            0x0010                                                \
        }                                                         \
    }
