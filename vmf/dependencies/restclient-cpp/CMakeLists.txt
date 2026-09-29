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

message("-- Extracting restclient-cpp")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/restclient-cpp-0.5.3.zip
                     DESTINATION ${DEPENDENCIES_DIRECTORY}/restclient-cpp)

file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3)

file(INSTALL      
     DESTINATION ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3
     FILES  ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-vmf.txt
     RENAME CMakeLists.txt
     TYPE FILE)

add_subdirectory(${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3
                 ${DEPENDENCIES_DIRECTORY}/build/restclient-cpp)
