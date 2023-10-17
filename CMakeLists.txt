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
cmake_minimum_required(VERSION 3.10.2)

set(CMAKE_VERBOSE_MAKEFILE ON)

# Specify project related variables.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_COMPILER g++)

# This is not an option that we want to enable.  Think twice about re-enabling it.
# Three times, maybe.  And then don't do it.  If some legacy code needs it, put it there
# somehow, not globally.
#add_compile_options(-fpermissive)

# Use address sanitizer?
#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#Added to prevent issues like this:
#https://stackoverflow.com/questions/61278099/using-stdthread-in-shared-library-causes-sigsegv
set(CMAKE_CXX_FLAGS -Wl,--no-as-needed)

project(Vader VERSION 3.1.0
    LANGUAGES CXX)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/vmf/cmake)

# Bring in VMF project wide variables and utility functions
include(vmf/cmake/vmf.cmake)
include(vmf/cmake/external_libs.cmake)

# Add in project directories
add_subdirectory(${PROJECT_SOURCE_DIR}/vmf/src)

# Create VADER Executable and link in dependencies.
# These dependencies are for the the VMF Framework
# not for specific modules
add_executable(vader ${PROJECT_SOURCE_DIR}/vmf/src/framework/main.cpp)
target_link_libraries(vader
  PRIVATE
  yaml
  VMFFramework
  stdc++fs
)
target_include_directories(vader PRIVATE 
  ${PROJECT_SOURCE_DIR}/vmf/src/framework/baseclasses
  ${PROJECT_SOURCE_DIR}/vmf/src/framework/app
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/formatter
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/initialization
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/inputgeneration
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/mutator
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/output
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/executor
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/feedback
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/initialization
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/mutator
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/output
)
set_vmf_compile_options(vader)
install(TARGETS vader
  RUNTIME DESTINATION ${VMF_INSTALL_BINDIR})

include(GoogleTest)
enable_testing()

add_subdirectory(${PROJECT_SOURCE_DIR}/test)

install(FILES "vmf/cmake/vmf.cmake" "vmf/cmake/vmf_imports.cmake"
  DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake)

install(DIRECTORY ${EXTERNAL_LIBDIR}
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  PATTERN "*.a" EXCLUDE
)

#Install samples project
install(DIRECTORY ${EXTERNAL_BINDIR}
  DESTINATION ${CMAKE_INSTALL_PREFIX}
  USE_SOURCE_PERMISSIONS
)

#Copy pre-built python klee script into vmf_install
install(DIRECTORY vmf/src/scripts/bin/
  DESTINATION ${VMF_INSTALL_BINDIR}
  USE_SOURCE_PERMISSIONS)

#Copy pre-built python klee script into local directory (for developers running directly from build)
add_custom_command(TARGET vader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/vmf/src/scripts/bin/* ${PROJECT_BINARY_DIR}/
)

#Header files are needed for plog library
install(DIRECTORY ${EXTERNAL_INCLUDEDIR}/plog 
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
