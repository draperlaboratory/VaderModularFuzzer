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

cmake_minimum_required(VERSION 3.10.2)

if(WIN32)
    # add_library(haystack_libfuzzer_lib SHARED haystack_libfuzzer.c)
    add_executable(haystack_libfuzzer haystack_libfuzzer.c)

    # set_target_properties(haystack_libfuzzer_lib PROPERTIES LANGUAGE C++)
    set_target_properties(haystack_libfuzzer PROPERTIES LANGUAGE C++)
    
    link_directories(${VMF_INSTALL_LIBDIR})
    target_link_libraries(haystack_libfuzzer vmf_frida_rtlib vmf_frida_rtembed shell32)
    target_link_options(haystack_libfuzzer PRIVATE /subsystem:console)

    install(TARGETS haystack_libfuzzer
        RUNTIME DESTINATION ./haystackSUT)
    # install(TARGETS haystack_libfuzzer_lib
    #     LIBRARY DESTINATION test/haystackSUT
    #     RENAME haystack_libfuzzer.dll)
endif()
