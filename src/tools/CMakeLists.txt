# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function(add_quic_tool)
    set(targetname ${ARGV0})
    list(REMOVE_AT ARGV 0)

    add_executable(${targetname} ${ARGV})
    target_link_libraries(${targetname} inc warnings msquic)

    if (BUILD_SHARED_LIBS)
        target_link_libraries(${targetname} msquic_platform)
    endif()

    target_link_libraries(${targetname} logging base_link)

    set_property(TARGET ${targetname} PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tools")
    set_property(TARGET ${targetname} APPEND PROPERTY BUILD_RPATH "$ORIGIN")
endfunction()

function(quic_tool_warnings)
    target_link_libraries(${ARGV0} warnings)
endfunction()

add_subdirectory(attack)
add_subdirectory(forwarder)
add_subdirectory(interop)
add_subdirectory(interopserver)
add_subdirectory(ip/client)
add_subdirectory(ip/server)
add_subdirectory(lb)
add_subdirectory(load)
add_subdirectory(pcp)
add_subdirectory(post)
add_subdirectory(sample)
add_subdirectory(spin)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # The NAT-traversal harness of #174. Linux and nothing else, which is the
    # scope rather than a convenience: the environment it exists to run in is
    # Linux network namespaces, so there is nowhere else for it to be useful.
    # "NOT WIN32" was wrong here -- it also builds for Darwin, iOS and Android.
    add_subdirectory(punch)
endif()
if(WIN32 AND (NOT QUIC_UWP_BUILD AND NOT QUIC_GAMECORE_BUILD))
    add_subdirectory(execution)
    add_subdirectory(etw)
    add_subdirectory(recvfuzz)
    add_subdirectory(xdpmap)
endif()
