# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (NOT WIN32) # __feature_io__
add_subdirectory(socket)
add_subdirectory(fs)
add_subdirectory(eventfd)

install(FILES
    fs/sgxfs/sgxfs.edl
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/edl")
endif()
