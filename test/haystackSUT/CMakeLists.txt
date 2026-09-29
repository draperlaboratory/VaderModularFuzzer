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
    # add_library(haystack_libfuzzer_lib SHARED haystack_libfuzzer.c)
    add_executable(haystack_libfuzzer haystack_libfuzzer.c)

    # set_target_properties(haystack_libfuzzer_lib PROPERTIES LANGUAGE C++)
    set_target_properties(haystack_libfuzzer PROPERTIES LANGUAGE C++)
    
    link_directories(${VMF_INSTALL_LIBDIR})
    target_link_libraries(haystack_libfuzzer vmf_frida_rtlib vmf_frida_rtembed shell32)
    target_link_options(haystack_libfuzzer PRIVATE /subsystem:console)

    install(TARGETS haystack_libfuzzer
        RUNTIME DESTINATION test/haystackSUT)
    # install(TARGETS haystack_libfuzzer_lib
    #     LIBRARY DESTINATION test/haystackSUT
    #     RENAME haystack_libfuzzer.dll)
else()
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts)
        set(LANGUAGE c)

        set(CMAKE_C_COMPILER ${AFL_CLANG_FAST})
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")
        
        add_executable(haystack haystack.c)
        add_executable(haystack_AFL_shmem haystack_AFL_shmem.c)
        add_executable(haystack_AFL_deferred haystack_AFL_deferred.c)
        add_executable(haystack_AFL_persist haystack_AFL_persist.c)

        if(NOT WIN32)
            # AFL++: The compiler-rt runtime (__afl_bug_configure_runtime) calls dlsym at startup to locate sanitizer symbols for fork-server coordination. This requires the dynamic linking API from libdl, which was a separate library until glibc 2.34 merged it into libc; -ldl is required on older glibc and harmless on newer. This work around is to support u20, centos8, oracle8, and rhel8 distributions.
            target_link_libraries(haystack ${CMAKE_DL_LIBS})
            target_link_libraries(haystack_AFL_shmem ${CMAKE_DL_LIBS})
            target_link_libraries(haystack_AFL_deferred ${CMAKE_DL_LIBS})
            target_link_libraries(haystack_AFL_persist ${CMAKE_DL_LIBS})
        endif()

        install(TARGETS haystack haystack_AFL_shmem haystack_AFL_deferred haystack_AFL_persist
            RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/test/haystackSUT)
    endif()
endif()
