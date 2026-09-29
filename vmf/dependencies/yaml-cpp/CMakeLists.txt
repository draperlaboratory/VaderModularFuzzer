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

#Disabled additional yaml targets
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE) 
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
#Add library, but exclude all the targets
message("-- Extracting yaml-cpp")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/yaml-cpp-0.9.0.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/yaml-cpp)
file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-0.9.0)
add_subdirectory(${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-0.9.0 ${DEPENDENCIES_DIRECTORY}/build/yaml-cpp/yaml-cpp-0.9.0 EXCLUDE_FROM_ALL)
