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
find_program(KLEE_EXEC klee)

if (KLEE_EXEC)
    message(STATUS "KLEE found: ${KLEE_EXEC}")

    set(SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/test/haystackSUT/haystack.c
    )
    
    add_custom_target(haystack.bc ALL
        COMMAND clang -emit-llvm -c -o haystack.bc ${SOURCE_FILES}
        DEPENDS ${SOURCE_FILES}
    )
else ()
    message(STATUS "KLEE not found.  Skipping KLEE bitcode generation.")
endif()