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
# VMF CMake file to be used by clients of an installed distribution of VMF where the
# clients are developing VMF modules.  Those modules need to link against the VMF
# 'common' library.  This file provides the import library definition they should use.
#

set(VMF_INSTALL_LIBDIR ${VMF_INSTALL}/lib)
set(VMF_INSTALL_INCLUDEDIR ${VMF_INSTALL}/include)

add_library(vmf_framework SHARED IMPORTED)
set_target_properties(vmf_framework PROPERTIES IMPORTED_LOCATION ${VMF_INSTALL_LIBDIR}/libVMFFramework.so)
set_target_properties(vmf_framework PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${VMF_INSTALL_INCLUDEDIR})
#target_include_directories(vmf_framework
#  INTERFACE
#  ${VMF_INSTALL_INCLUDEDIR}
#)
