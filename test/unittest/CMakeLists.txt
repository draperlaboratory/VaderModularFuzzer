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

# required by gtest
find_package(Threads REQUIRED)

add_library(VmfTestLib STATIC
    TestConfigInterface.cpp
    ModuleTestHelper.cpp)
target_include_directories(VmfTestLib PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ../../vmf/src/framework/app/
    ./
)
target_link_libraries(VmfTestLib
  PRIVATE
  gtest 
  gtest_main
  VMFFramework
  CoreModules
  Threads::Threads
  yaml-cpp
)

SET(TEST_SRCS
  ../../vmf/src/framework/app/ConfigManager.cpp
  ../../vmf/src/framework/app/ModuleManager.cpp
  TestConfigInterfaceTest.cpp
  TestAll.cpp
  ConfigManagerTest.cpp
  StorageRegistryTest.cpp
  StorageModuleTest.cpp
  StorageModuleTestFloat.cpp
  AFLMutatorTest.cpp
  GAInputGenTest.cpp
  DictionaryMutatorTest.cpp
  TrivialSeedInitializationTest.cpp
  OutputSchedulerTest.cpp
  MOPTTest.cpp
)

if(WIN32)
   list(APPEND TEST_SRCS
      windows/FridaExecutorTest.cpp
   )
   #windows-specific unit tests
else()
   #linux-specific unit tests
    list(APPEND TEST_SRCS
          linux/AFLForkserverExecutorTest.cpp
          linux/DictionaryInitializationTest.cpp
	)
endif()

add_executable(VmfTest ${TEST_SRCS})

set_target_properties(VmfTest PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(VmfTest PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ../../vmf/src/framework/app/
    ./
)

if(WIN32)
   target_compile_definitions(VmfTest PRIVATE PLOG_IMPORT)
endif()

target_link_libraries(VmfTest
  PRIVATE
  VmfTestLib
  PUBLIC
  gtest 
  gtest_main
  VMFFramework
  CoreModules
  Threads::Threads
  PRIVATE
  yaml-cpp
)
gtest_discover_tests(VmfTest WORKING_DIRECTORY ${CMAKE_BINARY_DIR}  DISCOVERY_MODE PRE_TEST)
