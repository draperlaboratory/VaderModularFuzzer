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
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")
        add_executable(magicbytes magicbytes.c)
        add_executable(magicbytes_cmplog magicbytes.c)
        
        set_target_properties(magicbytes_cmplog PROPERTIES LANGUAGE C)
        set_target_properties(magicbytes_cmplog PROPERTIES 
            RULE_LAUNCH_COMPILE "AFL_LLVM_CMPLOG=1")

        if(NOT WIN32)
            # AFL++: The compiler-rt runtime (__afl_bug_configure_runtime) calls dlsym at startup to locate sanitizer symbols for fork-server coordination. This requires the dynamic linking API from libdl, which was a separate library until glibc 2.34 merged it into libc; -ldl is required on older glibc and harmless on newer. This work around is to support u20, centos8, oracle8, and rhel8 distributions.
            target_link_libraries(magicbytes ${CMAKE_DL_LIBS})
            target_link_libraries(magicbytes_cmplog ${CMAKE_DL_LIBS})
        endif()
        
        install(TARGETS magicbytes magicbytes_cmplog
            RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/test/magicBytesSUT)
    endif()
endif()
