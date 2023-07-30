#===============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
# <vader@draper.com>
#  
# Effort sponsored by the U.S. Government under Other Transaction number
# W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
# Is authorized to reproduce and distribute reprints for Governmental purposes
# notwithstanding any copyright notation thereon.
#  
# The views and conclusions contained herein are those of the authors and
# should not be interpreted as necessarily representing the official policies
# or endorsements, either expressed or implied, of the U.S. Government.
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
add_library(VMFFramework SHARED
    app/BaseException.cpp
    app/CDMSClient.cpp
    app/ConfigInterface.cpp
    app/ConfigManager.cpp
    app/json11.cpp
    app/Logging.cpp
    app/ModuleFactory.cpp
    app/Plugins.cpp
    app/RuntimeException.cpp
    app/VaderApplication.cpp
    app/VaderUtil.cpp
    baseclasses/ControllerModule.cpp
    baseclasses/IterativeController.cpp
    baseclasses/OutputScheduler.cpp
    baseclasses/RunOnceController.cpp
    baseclasses/SimpleIterator.cpp
    baseclasses/SimpleStorage.cpp
    baseclasses/StorageEntry.cpp
    baseclasses/StorageRegistry.cpp
)

target_link_libraries(VMFFramework
  PRIVATE
  yaml
  restclient
)

target_include_directories(VMFFramework PUBLIC
  ${PROJECT_SOURCE_DIR}/vmf/src/framework/baseclasses
  ${PROJECT_SOURCE_DIR}/vmf/src/framework/app
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/formatter
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/initilization
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/inputgeneration
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/mutator
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/output
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/executor
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/feedback
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/initialization
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/mutator
  ${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/output
)

set_vmf_compile_options(VMFFramework)

install(TARGETS VMFFramework
  LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR}
)

# install public headers

file(GLOB PUBLIC_HEADERS app/*.hpp baseclasses/*.hpp)
install(FILES ${PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vmf COMPONENT CPP_INCLUDES)
