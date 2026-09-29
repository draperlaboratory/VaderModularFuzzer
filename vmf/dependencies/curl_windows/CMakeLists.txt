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
file(GLOB CURL_PKG ${CMAKE_CURRENT_SOURCE_DIR}/curl*vmf.zip)

message("-- Extracting curl_windows")
file(ARCHIVE_EXTRACT INPUT ${CURL_PKG} DESTINATION ${DEPENDENCIES_DIRECTORY}/curl )
file(COPY ${DEPENDENCIES_DIRECTORY}/curl/bin/libcurl.dll DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
find_package(CURL REQUIRED PATHS ${DEPENDENCIES_DIRECTORY}/curl/lib/cmake/CURL)
install(IMPORTED_RUNTIME_ARTIFACTS CURL::libcurl_shared RUNTIME)
