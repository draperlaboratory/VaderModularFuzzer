#===============================================================================
# Vader Modular Fuzzer
# Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
# <vader@draper.com>
# 
# Effort sponsored by the U.S. Government under Other Transaction number
# W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
# is authorized to reproduce and distribute reprints for Governmental purposes
# notwithstanding any copyright notation thereon.
# 
# The views and conclusions contained herein are those of the authors and
# should not be interpreted as necessarily representing the official policies
# or endorsements, either expressed or implied, of the U.S. Government.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
# 
# @license GPL-3.0-or-later <https://spdx.org/licenses/GPL-3.0-or-later>
#===============================================================================
cmake_minimum_required(VERSION 3.10.2)

# Specify project related variables.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#Clang or g++ are supported
set(CMAKE_CXX_COMPILER g++)
#set(CMAKE_CXX_COMPILER clang++)

project(Vader VERSION 2.0
    LANGUAGES CXX)

# Based on https://github.com/Sarcasm/cmake-superbuild
# Handle superbuild first
# option (USE_SUPERBUILD "Whether or not a superbuild should be invoked" ON)

include(${PROJECT_SOURCE_DIR}/../cmake/vmf_utils.cmake)

message("-- Building Dependencies for VADER...")
include (cmake/superbuild.cmake)
message("-- Dependent Projects built...")

get_debian_version(DEBIAN_VERSION)
set(DELIVER_BASE_DIR ${PROJECT_SOURCE_DIR}/../external/${DEBIAN_VERSION})
message("delivering to ${DELIVER_BASE_DIR}")
install(DIRECTORY ${CMAKE_BINARY_DIR}/external/bin
  DESTINATION ${DELIVER_BASE_DIR}
  USE_SOURCE_PERMISSIONS
)
install(DIRECTORY ${CMAKE_BINARY_DIR}/external/include
  DESTINATION ${DELIVER_BASE_DIR}
)
install(DIRECTORY ${CMAKE_BINARY_DIR}/external/lib
  DESTINATION ${DELIVER_BASE_DIR}
  PATTERN "cmake" EXCLUDE
  PATTERN "pkgconfig" EXCLUDE
)
