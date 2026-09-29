#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
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

# Product depdendency libs. These are built statically and linked to VMFFramework
# Suppress warnings in 3rd party code
set(BUILD_SHARED_LIBS off)
add_compile_options(-w)
add_compile_options(-fPIC)
set(DEPENDENCIES_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts/deps)

function(extract_and_build_dep PKG PKG_NAME INCLUDE_PATH)
  message("-- Extracting ${PKG_NAME}")
  file(ARCHIVE_EXTRACT INPUT ${PKG} DESTINATION  ${DEPENDENCIES_DIRECTORY}/${PKG_NAME})
  file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/${PKG_NAME}/${PKG_NAME}-*)
  list(GET matched_dirs 0 matched_dir)
  file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/${INCLUDE_PATH})
  add_subdirectory(${DEPENDENCIES_DIRECTORY}/${INCLUDE_PATH} ${DEPENDENCIES_DIRECTORY}/build/${PKG_NAME})
endfunction()

if(WIN32)
    message("-- Including windows dependencies")
    add_subdirectory(wingetopt)
    add_subdirectory(curl_windows)

    #windows-only dependencies
    if(NOT DEFINED FRIDA_PKG)
        set(
            FRIDA_PKG "${CMAKE_CURRENT_SOURCE_DIR}/frida/frida-gum-devkit-17.9.10-windows-x86_64.tar.xz" 
            CACHE STRING "Path to selected frida binary"
        )
    endif()
else()
    message("-- Including linux dependencies")
    add_subdirectory(klee)
endif()

add_subdirectory(googletest)
add_subdirectory(plog)
add_subdirectory(yaml-cpp)
add_subdirectory(uthash)
add_subdirectory(json11)
add_subdirectory(restclient-cpp)