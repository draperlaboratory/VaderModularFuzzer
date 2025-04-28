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
# Sample Module
cmake_minimum_required(VERSION 3.10)

# Specify project related variables.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#Clang or g++ are supported
#set(CMAKE_CXX_COMPILER g++)
#set(CMAKE_CXX_COMPILER clang++)

project(ModuleTemplates VERSION 1.0 LANGUAGES CXX)

#Set flag to export all symbols for windows builds
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Check that CMAKE_INSTALL_PREFIX directory is properly defined, exit with error if not
if (NOT IS_DIRECTORY ${CMAKE_INSTALL_PREFIX})
  message( "CMAKE_INSTALL_PREFIX: " ${CMAKE_INSTALL_PREFIX} )
  message( FATAL_ERROR "CMake variable CMAKE_INSTALL_PREFIX must be defined as full path to a VMF install tree, please use cmake -DCMAKE_INSTALL_PREFIX=/full/path/to/VMF" )
endif()


# Bring in VMF support variables and utility functions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/cmake")
include(vmf_imports)
include(vmf)

add_library(ModuleTemplates SHARED
  TemplateExecutor.cpp
  TemplateFeedback.cpp
  TemplateInitialization.cpp
  TemplateInputGenerator.cpp
  TemplateMutator.cpp
  TemplateOutput.cpp
)
# set VMF standard compile options
set_vmf_compile_options(ModuleTemplates)


# windows needs an additional import to make the logger work
if(WIN32)
   target_compile_definitions(ModuleTemplates PRIVATE PLOG_IMPORT)
endif()

#include the vmf framework headers
target_include_directories(ModuleTemplates
  PUBLIC
  ${CMAKE_INSTALL_PREFIX}/include
  ${CMAKE_INSTALL_PREFIX}/include/vmf
  ${CMAKE_INSTALL_PREFIX}/include/plog
)

#link to the vmf framework library
target_link_libraries(ModuleTemplates
  PUBLIC
  vmf_framework
)

#install build library into vmf plugins directory
install(TARGETS ModuleTemplates
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plugins
)

#On windows the /plugins directory above is ignored, and everything ends up in /lib and /bin
if(WIN32)
  cmake_path(SET WIN_LIB_FILE ${CMAKE_INSTALL_PREFIX}/lib/ModuleTemplates.lib)
  cmake_path(SET WIN_DLL_FILE ${CMAKE_INSTALL_PREFIX}/bin/ModuleTemplates.dll)
  install(FILES ${WIN_LIB_FILE} ${WIN_DLL_FILE}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/plugins)
endif()
