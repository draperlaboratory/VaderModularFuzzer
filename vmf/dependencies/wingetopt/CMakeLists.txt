#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
# <vader@draper.com>
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

#This make file wraps source code from wingetopt.  See: https://github.com/alex85k/wingetopt

message("-- Extracting wingetopt")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/wingetopt-1.00.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/wingetopt)
add_library(getopt STATIC ${DEPENDENCIES_DIRECTORY}/wingetopt/wingetopt-1.00/src/getopt.c)
target_include_directories(getopt PUBLIC ${DEPENDENCIES_DIRECTORY}/wingetopt/wingetopt-1.00/src)
