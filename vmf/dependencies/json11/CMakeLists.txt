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
message("-- Extracting json11")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/json11-1.0.0.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/json11)

file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/json11/json11-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0)

add_library(json11 STATIC ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0/json11.cpp)
target_include_directories(json11 PUBLIC ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0)

#json11 1.0.0 uses uint8_t without including cstdint, which newer toolchains reject, so force the header for this target only
if(MSVC)
  target_compile_options(json11 PRIVATE /FIcstdint)
else()
  target_compile_options(json11 PRIVATE -include cstdint)
endif()

install(FILES ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0/json11.hpp DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vmf COMPONENT CPP_INCLUDES)

