#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
# <vmf@draper.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 (only) as 
# published by the Free Software Foundation.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#  
# @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
#===============================================================================

cmake_minimum_required(VERSION 3.10.2)
if(WIN32)
else()
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(CMAKE_C_COMPILER ${AFL_CLANG_FAST})
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")

        add_executable(mime mime.c)
        add_executable(mime_asan mime.c)

        set(BINARY_SOURCE ${CMAKE_SOURCE_DIR}/test/unittest/inputs/AFLForkserverExecutorTest/mimeSUT/mime_legacy)
        set(BINARY_DEST ${CMAKE_BINARY_DIR}/build_artifacts/mime_legacy)
        add_custom_command(
            OUTPUT ${BINARY_DEST}
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${BINARY_SOURCE} ${BINARY_DEST}
            DEPENDS ${BINARY_SOURCE}
            COMMENT "Copying ${BINARY_SOURCE} to ${BINARY_DEST}"
        )
        add_custom_target(copy_binary ALL DEPENDS ${BINARY_DEST})
        
        set_target_properties(mime PROPERTIES LANGUAGE C)
        set_target_properties(mime_asan PROPERTIES LANGUAGE C)

        if(NOT WIN32)
            # AFL++: The compiler-rt runtime (__afl_bug_configure_runtime) calls dlsym at startup to locate sanitizer symbols for fork-server coordination. This requires the dynamic linking API from libdl, which was a separate library until glibc 2.34 merged it into libc; -ldl is required on older glibc and harmless on newer. This work around is to support u20, centos8, oracle8, and rhel8 distributions.
            target_link_libraries(mime ${CMAKE_DL_LIBS})
            target_link_libraries(mime_asan ${CMAKE_DL_LIBS})
        endif()

        target_compile_options(mime_asan PRIVATE -fsanitize=address -g)
        target_link_options(mime_asan PRIVATE -fsanitize=address)
    endif()
endif()
