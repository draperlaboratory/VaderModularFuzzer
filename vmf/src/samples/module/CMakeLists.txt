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
# Sample Module
cmake_minimum_required(VERSION 3.10)

# Specify project related variables.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#Clang or g++ are supported
set(CMAKE_CXX_COMPILER g++)
#set(CMAKE_CXX_COMPILER clang++)

project(MyModule VERSION 1.0 LANGUAGES CXX)

# include support cmake files
include(${VMF_INSTALL}/cmake/vmf_imports.cmake)
include(${VMF_INSTALL}/cmake/vmf.cmake)

add_library(MyModule SHARED
  MyMutator.cpp
)
# set VMF standard compile options
set_vmf_compile_options(MyModule)

#include the vmf framework headers
target_include_directories(MyModule
  PUBLIC
  ${VMF_INSTALL}/include/vmf
)

#link to the vmf framework library
target_link_libraries(MyModule
  PUBLIC
  vmf_framework
)

#install build library into vmf plugins directory
install(TARGETS MyModule
  LIBRARY DESTINATION ${VMF_INSTALL}/plugins
)