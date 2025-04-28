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
# VMF CMake file to be used by clients of an installed distribution of VMF where the
# clients are developing VMF modules.  Those modules need to link against the VMF
# 'common' library.  This file provides the import library definition they should use.
#

include(GNUInstallDirs)
set(VMF_INSTALL_LIBDIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(VMF_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_PREFIX}/include)

# Export all symbols for windows
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(vmf_framework SHARED IMPORTED)
if(WIN32)
set_target_properties(vmf_framework PROPERTIES IMPORTED_LOCATION ${VMF_INSTALL_LIBDIR}/VMFFramework.dll)
else()
set_target_properties(vmf_framework PROPERTIES IMPORTED_LOCATION ${VMF_INSTALL_LIBDIR}/libVMFFramework.so)
endif()
set_target_properties(vmf_framework PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${VMF_INSTALL_INCLUDEDIR})
#target_include_directories(vmf_framework
#  INTERFACE
#  ${VMF_INSTALL_INCLUDEDIR}
#)

#Windows needs additional paths to the .lib file, as it is needed at compile time
#(And this has to be here, and not in vmf_imports.cmake, or it doesn't work right)
if(WIN32)
    set(VMF_ADDITIONAL_PATH ${CMAKE_INSTALL_PREFIX}/lib/VMFFramework.lib)
    set_target_properties(vmf_framework PROPERTIES IMPORTED_IMPLIB ${VMF_ADDITIONAL_PATH})
    # Windows insists on this being set for each type of build (e.g. Debug, Release, etc)
    foreach( OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES} )
        string( TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG )
        set_target_properties(vmf_framework PROPERTIES IMPORTED_IMPLIB_${OUTPUTCONFIG} ${VMF_ADDITIONAL_PATH})
    endforeach( OUTPUTCONFIG CMAKE_CONFIGURATION_TYPES )
endif()

