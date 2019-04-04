# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../deepcopy.edl enclave gen)

add_enclave(TARGET deepcopy_enc SOURCES enc.c ${gen})

target_include_directories(deepcopy_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(deepcopy_enc oelibc)
