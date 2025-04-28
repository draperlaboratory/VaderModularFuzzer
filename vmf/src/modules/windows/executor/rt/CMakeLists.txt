# =============================================================================
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
# ===========================================================================
set(FRIDA_ARTIFACTS "*.lib")
if(WIN32)
  file(ARCHIVE_EXTRACT INPUT ${FRIDA_PKG} DESTINATION ${CMAKE_BINARY_DIR}/include/frida PATTERNS "*.h" )
  file(ARCHIVE_EXTRACT INPUT ${FRIDA_PKG} DESTINATION ${CMAKE_BINARY_DIR}/lib/frida PATTERNS "*.lib" )
  add_library(frida_gum STATIC IMPORTED)
  set_target_properties( frida_gum PROPERTIES IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/lib/frida/frida-gum.lib
                          INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/include/frida 
                        )
  add_library( vmf_frida_rtembed SHARED "vmfFrida_driver.cpp" "configService.cpp" "vmfFrida_instrumenter.cpp")
  target_link_libraries( vmf_frida_rtembed PRIVATE frida_gum getopt yaml-cpp)
  target_compile_definitions( vmf_frida_rtembed PRIVATE GUM_STATIC )
  target_link_options( vmf_frida_rtembed PRIVATE LINKER:/NODEFAULTLIB:libcmt )
  set_target_properties( vmf_frida_rtembed PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS FALSE)  
  add_library( vmf_frida_rtlib STATIC "main.c")

  add_executable( vmf_frida_rtentry main.c)
  target_link_libraries( vmf_frida_rtentry PRIVATE frida_gum vmf_frida_rtembed)
  target_compile_definitions( vmf_frida_rtentry PRIVATE VMF_TEST_ENTRY_DYNAMIC )
 
  install(TARGETS vmf_frida_rtlib LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR})
  install(TARGETS vmf_frida_rtembed LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR})
  install(TARGETS vmf_frida_rtentry RUNTIME DESTINATION ${VMF_INSTALL_BINDIR})
 
endif()



