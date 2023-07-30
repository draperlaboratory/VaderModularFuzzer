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
# This CMake file sets up imported libraries for the prebuilt external dependencies
# for the VMF build.
#

# for get_debian_version
include(vmf_utils)

#
# We use the Debian version to distinguish which prebuilt-externals we use.
# Ubuntu 18 has Debian version 'buster'
# Ubuntu 20 has Debian version 'bullseye'
#
get_debian_version(DEBIAN_VERSION)


if(NOT DEFINED EXTERNAL_BASE)
    set(EXTERNAL_BASE ${PROJECT_SOURCE_DIR}/vmf/external/${DEBIAN_VERSION})
endif()

set(EXTERNAL_BINDIR ${EXTERNAL_BASE}/bin)
set(EXTERNAL_LIBDIR ${EXTERNAL_BASE}/lib)
set(EXTERNAL_INCLUDEDIR ${EXTERNAL_BASE}/include)

#
# IMPORTED_NO_SONAME is used here to prevent relative paths from being used in the SO names
# written to the ELF files linked against these libraries.  Those present issues when other
# builds try to link against them.  RPATH is used to resolve load time search paths instead.
#

#
# We would like to use target_include_directories, below, but CMake version 3.10
# doesn't support it.  So that's why we have to do the awful nonsense with
# set_property.  If we move to a newer version of CMake, we can get rid of the hack.
#

set(AFLPP_LIB ${EXTERNAL_LIBDIR}/libaflpp.so)
add_library(AFLPP SHARED IMPORTED)
set_target_properties(AFLPP PROPERTIES IMPORTED_LOCATION ${AFLPP_LIB} IMPORTED_NO_SONAME TRUE)
# see note above:
set_property(TARGET AFLPP APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(AFLPP
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

set(AFL_legacy_LIB ${EXTERNAL_LIBDIR}/libafl.so)
add_library(AFL_legacy SHARED IMPORTED)
set_target_properties(AFL_legacy PROPERTIES IMPORTED_LOCATION ${AFL_legacy_LIB} IMPORTED_NO_SONAME TRUE)
# see note above:
set_property(TARGET AFL_legacy APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(AFL_legacy
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

set(YAML_LIB ${EXTERNAL_LIBDIR}/libyaml-cpp.so)
add_library(yaml SHARED IMPORTED)
set_target_properties(yaml PROPERTIES IMPORTED_LOCATION ${YAML_LIB} IMPORTED_NO_SONAME TRUE)
# see note above:
set_property(TARGET yaml APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(yaml
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

set(RADAMSA_LIB ${EXTERNAL_LIBDIR}/libradamsa.so)
add_library(radamsa SHARED IMPORTED)
set_target_properties(radamsa PROPERTIES IMPORTED_LOCATION ${RADAMSA_LIB} IMPORTED_NO_SONAME TRUE)
# no one uses any header files for radamsa
#target_include_directories(radamsa
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

#find_package(Threads REQUIRED)
set(GTEST_LIB ${EXTERNAL_LIBDIR}/libgtest.a)
add_library(gtest STATIC IMPORTED)
set_target_properties(gtest PROPERTIES IMPORTED_LOCATION ${GTEST_LIB})
# I want to add pthreads to this library, because it is a dependency, but
# cmake doesn't like this with imported libraries.
#target_link_libraries(gtest PUBLIC Threads::Threads)
# see note above:
set_property(TARGET gtest APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(gtest
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

set(GTEST_MAIN_LIB ${EXTERNAL_LIBDIR}/libgtest_main.a)
add_library(gtest_main STATIC IMPORTED)
set_target_properties(gtest_main PROPERTIES IMPORTED_LOCATION ${GTEST_MAIN_LIB})
# see note above:
set_property(TARGET gtest_main APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(gtest_main
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)

set(RESTCLIENT_LIB ${EXTERNAL_LIBDIR}/librestclient-cpp.so)
add_library(restclient SHARED IMPORTED)
set_target_properties(restclient PROPERTIES IMPORTED_LOCATION ${RESTCLIENT_LIB} IMPORTED_NO_SONAME TRUE)
# see note above:
set_property(TARGET restclient APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EXTERNAL_INCLUDEDIR})
#target_include_directories(restclient
#  INTERFACE
#  ${EXTERNAL_INCLUDEDIR}
#)
