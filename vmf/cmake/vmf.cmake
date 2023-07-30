#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
# <vader@draper.com>
#  
# Effort sponsored by the U.S. Government under Other Transaction number
# W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
# Is authorized to reproduce and distribute reprints for Governmental purposes
# notwithstanding any copyright notation thereon.
#  
# The views and conclusions contained herein are those of the authors and
# should not be interpreted as necessarily representing the official policies
# or endorsements, either expressed or implied, of the U.S. Government.
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
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")

#
# Utility function to set a base set of compiler options on a target.  If you
# add a target (e.g., a library) to the build, you are expected to apply this
# function to it.
#
function (set_vmf_compile_options target)
  target_compile_options(${target}
    PRIVATE
    -Wall
    -Wextra
    # -Wextra turns on unused-parameter, but we don't want that one currently?
    -Wno-unused-parameter
    -Werror
    )
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
