#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
# <vmf@draper.com>
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
cmake_minimum_required(VERSION 3.10.2)

#set(CMAKE_VERBOSE_MAKEFILE ON)

# Specify project related variables.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#Clang or g++ are supported
set(CMAKE_CXX_COMPILER g++)
#set(CMAKE_CXX_COMPILER clang++)

# This is not an option that we want to enable.  Think twice about re-enabling it.
# Three times, maybe.  And then don't do it.  If some legacy code needs it, put it there
# somehow, not globally.
#add_compile_options(-fpermissive)

# Use address sanitizer?
#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

# Add debug info?
#add_link_options(-g)
#add_compile_options(-g)

# produce compile_commands.json for clangd support
set(CMAKE_EXPORT_COMPILE_COMMANDS True)

#############################################################
project(VMF VERSION 4.0.0
    LANGUAGES CXX )
#############################################################

# Bring in VMF project wide variables and utility functions
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/vmf/cmake)
include(vmf)

# Add in project directories
add_subdirectory(vmf)

include(GoogleTest)
enable_testing()

add_subdirectory(${PROJECT_SOURCE_DIR}/test)

install(FILES "vmf/cmake/vmf.cmake" "vmf/cmake/vmf_imports.cmake"
  DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake)

#Copy support scripts into vmf_install
install(DIRECTORY vmf/src/scripts/bin/
  DESTINATION ${VMF_INSTALL_BINDIR}
  USE_SOURCE_PERMISSIONS)

#Header files are needed for plog library
install(DIRECTORY vmf/dependencies/plog/include/plog
  DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
)

install(DIRECTORY vmf/src/samples
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  PATTERN "build" EXCLUDE)

#install sample configuration files and haystack example
INSTALL(DIRECTORY test DESTINATION 
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  PATTERN "*.cpp" EXCLUDE
  PATTERN "*.txt" EXCLUDE
  PATTERN "haystack" EXCLUDE
  PATTERN "magicbytes" EXCLUDE
  PATTERN "magicbytes_cmplog" EXCLUDE    
  PATTERN "setup_jerryscript" EXCLUDE
  PATTERN "test_only" EXCLUDE
  PATTERN "test_only/*" EXCLUDE
  PATTERN "unittest" EXCLUDE
)

#install data directory
INSTALL(DIRECTORY data DESTINATION 
  DESTINATION ${CMAKE_INSTALL_PREFIX}
)

#install haystack example executable
file (COPY test/haystackSUT/haystack
DESTINATION ${CMAKE_INSTALL_PREFIX}/test/haystackSUT
USE_SOURCE_PERMISSIONS)

#install magicbytes executable
file (COPY test/magicBytesSUT/magicbytes
DESTINATION ${CMAKE_INSTALL_PREFIX}/test/magicBytesSUT
USE_SOURCE_PERMISSIONS)

#install magicbytes_cmplog executable
file (COPY test/magicBytesSUT/magicbytes_cmplog
DESTINATION ${CMAKE_INSTALL_PREFIX}/test/magicBytesSUT/
USE_SOURCE_PERMISSIONS)
