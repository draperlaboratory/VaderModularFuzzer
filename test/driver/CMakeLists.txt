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

if(NOT WIN32)
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts)
        set(LANGUAGE c)

        set(CMAKE_C_COMPILER ${AFL_CLANG_FAST})
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")
        
	add_library(VMFDriver STATIC VMFDriver.c)

	install(TARGETS VMFDriver
	    LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR})
    endif()
endif()
