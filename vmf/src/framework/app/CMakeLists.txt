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

add_executable(vader
    main.cpp
    ConfigManager.cpp    
    ModuleManager.cpp    
    Plugins.cpp
    VmfApplication.cpp
)

if(WIN32)
   target_compile_definitions(vader PRIVATE PLOG_IMPORT)
endif()

set(VADER_PRIVATE_LINKLIST
  plog
)

target_link_libraries(vader 
    PUBLIC 
        VMFFramework
        yaml-cpp
    PRIVATE
	${VADER_PRIVATE_LINKLIST}
)
set_vmf_compile_options(vader)
set_target_properties(vader PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

install(TARGETS vader
  RUNTIME DESTINATION ${VMF_INSTALL_BINDIR})
