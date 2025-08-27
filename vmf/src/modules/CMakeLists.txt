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
# Create Core Modules Library
set(CoreModules_SOURCES )

if(WIN32)
   add_subdirectory(windows/executor/rt)
   list(APPEND CoreModules_SOURCES
        windows/executor/FridaExecutor.cpp
        #windows/executor/TBD.cpp
   )
else()
    list(APPEND CoreModules_SOURCES
        linux/executor/AFLForkserverExecutor.cpp
        linux/initialization/KleeInitialization.cpp
        linux/initialization/StringsInitialization.cpp
        linux/initialization/DictionaryInitialization.cpp
    )
endif()


list(APPEND CoreModules_SOURCES
    common/controller/AnalysisController.cpp
    common/controller/RunOnceController.cpp
    common/controller/IterativeController.cpp
    common/controller/NewCoverageController.cpp
    common/controller/BalancedController.cpp
    common/feedback/AFLCoverageUtil.cpp
    common/feedback/AFLFeedback.cpp
    common/feedback/AFLFavoredFeedback.cpp
    common/initialization/DirectoryBasedSeedGen.cpp
    common/initialization/GramatronBasedSeedGen.cpp
    common/initialization/ServerCorpusInitialization.cpp
    common/initialization/ServerSeedInitialization.cpp
    common/initialization/TrivialSeedInitialization.cpp
    common/inputgeneration/GeneticAlgorithmInputGenerator.cpp
    common/inputgeneration/MOPTInputGenerator.cpp    
    common/inputgeneration/MOPT.cpp
    common/inputgeneration/MOPTSwarm.cpp
    common/inputgeneration/RedPawnInputGenerator.cpp
    common/inputgeneration/RedPawnTransforms.cpp
    common/mutator/Gramatron.cpp
    common/mutator/GramatronHelpers.cpp
    common/mutator/GramatronPDA.cpp
    common/mutator/GramatronRandomMutator.cpp
    common/mutator/GramatronSpliceMutator.cpp
    common/mutator/GramatronRecursiveMutator.cpp
    common/mutator/GramatronGenerateMutator.cpp
    common/mutator/AFLFlipBitMutator.cpp
    common/mutator/AFLFlip2BitMutator.cpp
    common/mutator/AFLFlip4BitMutator.cpp
    common/mutator/AFLFlipByteMutator.cpp
    common/mutator/AFLFlip2ByteMutator.cpp
    common/mutator/AFLFlip4ByteMutator.cpp
    common/mutator/AFLRandomByteAddSubMutator.cpp
    common/mutator/AFLRandomByteMutator.cpp
    common/mutator/AFLDeleteMutator.cpp
    common/mutator/AFLCloneMutator.cpp
    common/mutator/AFLSpliceMutator.cpp
    common/mutator/DictionaryMutator.cpp
    common/mutator/StackedMutator.cpp
    common/mutator/MutatorSelector.cpp
    common/output/ComputeStats.cpp
    common/output/CorpusMinimization.cpp
    common/output/CSVMetadataOutput.cpp
    common/output/LoggerMetadataOutput.cpp
    common/output/SaveCorpusOutput.cpp
    common/output/ServerCorpusMinOutput.cpp
    common/output/ServerCorpusOutput.cpp
    common/output/StatsOutput.cpp
)

add_library(CoreModules SHARED ${CoreModules_SOURCES})

if(WIN32)
   target_compile_definitions(CoreModules PRIVATE PLOG_IMPORT)
endif()

#These are the dependencies for the VMF CoreModules
target_link_libraries(CoreModules
  PUBLIC
    VMFFramework
  PRIVATE        
    uthash
)

set(CoreModules_INCLUDES )

list(APPEND CoreModules_INCLUDES
  ${CMAKE_CURRENT_LIST_DIR}/util
  ${CMAKE_CURRENT_LIST_DIR}/common/controller
  ${CMAKE_CURRENT_LIST_DIR}/common/executor
  ${CMAKE_CURRENT_LIST_DIR}/common/feedback
  ${CMAKE_CURRENT_LIST_DIR}/common/initialization
  ${CMAKE_CURRENT_LIST_DIR}/common/inputgeneration
  ${CMAKE_CURRENT_LIST_DIR}/common/mutator
  ${CMAKE_CURRENT_LIST_DIR}/common/output
)

if(WIN32)
   list(APPEND CoreModules_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/windows/controller
    ${CMAKE_CURRENT_LIST_DIR}/windows/executor
    ${CMAKE_CURRENT_LIST_DIR}/windows/feedback
    ${CMAKE_CURRENT_LIST_DIR}/windows/initialization
    ${CMAKE_CURRENT_LIST_DIR}/windows/inputgeneration
    ${CMAKE_CURRENT_LIST_DIR}/windows/mutator
    ${CMAKE_CURRENT_LIST_DIR}/windows/output
    )
else()
  list(APPEND CoreModules_INCLUDES
    ${CMAKE_CURRENT_LIST_DIR}/linux/controller
    ${CMAKE_CURRENT_LIST_DIR}/linux/executor
    ${CMAKE_CURRENT_LIST_DIR}/linux/feedback
    ${CMAKE_CURRENT_LIST_DIR}/linux/initialization
    ${CMAKE_CURRENT_LIST_DIR}/linux/inputgeneration
    ${CMAKE_CURRENT_LIST_DIR}/linux/mutator
    ${CMAKE_CURRENT_LIST_DIR}/linux/output
  )
endif()

target_include_directories(CoreModules PUBLIC ${CoreModules_INCLUDES})

set_vmf_compile_options(CoreModules)

install(TARGETS CoreModules DESTINATION "${CMAKE_INSTALL_PREFIX}/plugins")

