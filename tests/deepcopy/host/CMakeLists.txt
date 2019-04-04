# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../deepcopy.edl host gen)

add_executable(deepcopy_host host.c ${gen})

target_include_directories(deepcopy_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(deepcopy_host oehostapp)
