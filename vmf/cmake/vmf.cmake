#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
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

#
# This file contains top level variables that specify locations and attributes
# specific to VMF.  There are also utility functions that aggregate common build
# support for VMF build targets.
#


# std::filesystem support is broken out into separate libs depending on compiler
# and version. Modern compilers don't need a lib separate from the standard one at all.
# This solves that problem by not defining std_filesystem_lib
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  set(std_filesystem_lib stdc++fs)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  set(std_filesystem_lib c++fs)
endif()


include(GNUInstallDirs)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/vmf_install" CACHE PATH "VMF install path" FORCE)
endif()

set(VMF_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(VMF_INSTALL_LIBDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(VMF_INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})

#
# This ensures that when executables are installed, the RPATH variable set in the ELF
# file will be one relative to the install location, and not an absolute.  This is
# key to making it possible to copy the entire install tree to another location and
# have it still run.  Otherwise, the loader will not be able to find all the shared
# libraries the executable(s) depend on.
#
set(CMAKE_INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")

#
# Utility function to set a base set of compiler options on a target.  If you
# add a target (e.g., a library) to the build, you are expected to apply this
# function to it.
#

function (set_vmf_compile_options target)
  if(WIN32)
    target_compile_definitions(${target} PRIVATE   
       # Prevents Windows.h from adding unnecessary includes    
       WIN32_LEAN_AND_MEAN  
       # Prevents Windows.h from defining min/max as macros 
       NOMINMAX 
       # Remove warnings about _s functions (that are Microsoft only implementations)
       _CRT_SECURE_NO_WARNINGS
       # Remove warnings about POSIX functions names (also Microsoft only)
       _CRT_NONSTDC_NO_WARNINGS
    )   
  else()
    target_compile_options(${target}
      PRIVATE
      -Wall
      -Wextra
      # -Wextra turns on unused-parameter, but we don't want that one currently?
      -Wno-unused-parameter
      -Werror
      )
  endif()
endfunction()

#
# For debugging when setup goes wrong
#
function (dump_vmf_vars)
  message("----- VMF Variables -----")
  message("-----")
  message("----- CMAKE_BINARY_DIR = ${CMAKE_BINARY_DIR}")
  message("----- CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")
  message("----- VMF_INSTALL_INCLUDEDIR = ${VMF_INSTALL_INCLUDEDIR}")
  message("----- VMF_INSTALL_LIBDIR = ${VMF_INSTALL_LIBDIR}")
  message("----- VMF_INSTALL_BINDIR = ${VMF_INSTALL_BINDIR}")
endfunction()

dump_vmf_vars()
