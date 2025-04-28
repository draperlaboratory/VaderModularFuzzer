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

# Create the common library.
set(Framework_SOURCES  
  util/BaseException.cpp
  util/CDMSClient.cpp
  util/CDMSCommandAndCorpusHandler.cpp
  util/ConfigInterface.cpp
  util/Logging.cpp
  util/ModuleFactory.cpp
  util/RuntimeException.cpp
  util/VmfUtil.cpp
  util/VmfRand.cpp
  baseclasses/ControllerModulePattern.cpp
  baseclasses/OutputScheduler.cpp
  baseclasses/SimpleIterator.cpp
  baseclasses/SimpleStorage.cpp
  baseclasses/StorageEntry.cpp
  baseclasses/StorageKeyHelper.hpp
  baseclasses/StorageRegistry.cpp
)

#conditionally add OS-specific files
if(WIN32)
  list(APPEND Framework_SOURCES 
    util/windows/OSAPIImp.cpp
    util/windows/UDPMulticastImp.cpp
  )
else()
  list(APPEND Framework_SOURCES 
    util/linux/OSAPIImp.cpp
    util/linux/UDPMulticastImp.cpp
    )
endif()

add_library(VMFFramework SHARED ${Framework_SOURCES})

set(Framework_LINKLIST
  plog
  json11
  restclient-cpp
)

if(NOT WIN32)
  list(APPEND Framework_LINKLIST stdc++fs)
else()
  list(APPEND Framework_LINKLIST wldap32 ws2_32 Crypt32.lib Wldap32 Normaliz)
endif()

#Logger requires additional export statement on windows
if(WIN32)
   target_compile_definitions(VMFFramework PRIVATE PLOG_EXPORT)
   set_target_properties(VMFFramework PROPERTIES ENABLE_EXPORTS 1)
endif()

set(Framework_PRIVATE_LINKLIST )

#getopt is not included automatically on windows
if(WIN32)
  list(APPEND Framework_PRIVATE_LINKLIST getopt)
endif()

target_link_libraries(VMFFramework
  PUBLIC
    ${Framework_LINKLIST}
  PRIVATE
    ${Framework_PRIVATE_LINKLIST}
)

set(Framework_INCLUDE  
  ${CMAKE_CURRENT_LIST_DIR}/baseclasses
  ${CMAKE_CURRENT_LIST_DIR}/util
)

#conditionally add OS-specific directory
if(WIN32)
  list(APPEND Framework_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/util/windows)
else()
  list(APPEND Framework_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/util/linux)
endif()

target_include_directories(VMFFramework PUBLIC ${Framework_INCLUDE})

set_vmf_compile_options(VMFFramework)

install(TARGETS VMFFramework
  LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR}
)

# install public headers

file(GLOB PUBLIC_HEADERS util/*.hpp baseclasses/*.hpp)
install(FILES ${PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vmf COMPONENT CPP_INCLUDES)



