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
# Create Core Modules Library
add_library(CoreModules SHARED
    linux/feedback/AFLFeedback.cpp
    linux/feedback/AFLFavoredFeedback.cpp
    linux/executor/AFLForkserverExecutor.cpp
    linux/initialization/KleeInitialization.cpp
    linux/initialization/StringsInitialization.cpp
    linux/mutator/AFLFlipBitMutator.cpp
    linux/mutator/AFLFlip2BitMutator.cpp
    linux/mutator/AFLFlip4BitMutator.cpp
    linux/mutator/AFLFlipByteMutator.cpp
    linux/mutator/AFLFlip2ByteMutator.cpp
    linux/mutator/AFLFlip4ByteMutator.cpp
    linux/mutator/AFLRandomByteAddSubMutator.cpp
    linux/mutator/AFLRandomByteMutator.cpp
    linux/mutator/AFLDeleteMutator.cpp
    linux/mutator/AFLCloneMutator.cpp
    linux/mutator/AFLSpliceMutator.cpp
    linux/mutator/RadamsaMutator.cpp
    linux/output/CorpusMinimization.cpp
    common/formatter/CRC32Formatter.cpp
    common/initialization/DirectoryBasedSeedGen.cpp
    common/initialization/GramatronBasedSeedGen.cpp
    common/initialization/ServerCorpusInitialization.cpp
    common/initialization/ServerSeedInitialization.cpp
    common/inputgeneration/GeneticAlgorithmInputGenerator.cpp
    common/inputgeneration/MOPTInputGenerator.cpp    
    common/inputgeneration/MOPT.cpp
    common/inputgeneration/MOPTSwarm.cpp
    common/mutator/Gramatron.cpp
    common/mutator/GramatronHelpers.cpp
    common/mutator/GramatronPDA.cpp
    common/mutator/GramatronRandomMutator.cpp
    common/mutator/GramatronSpliceMutator.cpp
    common/mutator/GramatronRecursiveMutator.cpp
    common/mutator/GramatronGenerateMutator.cpp
    common/output/SaveCorpusOutput.cpp
    common/output/ServerCorpusMinOutput.cpp
    common/output/ServerCorpusOutput.cpp
    common/output/StatsOutput.cpp
)

#These are the dependencies for the VMF CoreModules
target_link_libraries(CoreModules
  PRIVATE
  radamsa
  AFLPP
  VMFFramework
  stdc++fs
)
target_include_directories(CoreModules PUBLIC
${PROJECT_SOURCE_DIR}/vmf/src/framework/baseclasses
${PROJECT_SOURCE_DIR}/vmf/src/framework/app
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/util
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/formatter
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/initialization
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/inputgeneration
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/mutator
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/common/output
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/executor
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/feedback
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/initialization
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/mutator
${PROJECT_SOURCE_DIR}/vmf/src/coremodules/linux/output
)

set_vmf_compile_options(CoreModules)

install(TARGETS CoreModules DESTINATION "${CMAKE_INSTALL_PREFIX}/plugins")

#For developers, copy plugins in build/plugins
add_custom_command(TARGET CoreModules PRE_BUILD 
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins)
add_custom_command(TARGET CoreModules POST_BUILD 
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/vmf/src/coremodules/*.so ${CMAKE_BINARY_DIR}/plugins/)
