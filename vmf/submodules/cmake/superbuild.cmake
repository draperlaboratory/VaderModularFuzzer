#===============================================================================
# Vader Modular Fuzzer
# Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
# <vader@draper.com>
# 
# Effort sponsored by the U.S. Government under Other Transaction number
# W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
# is authorized to reproduce and distribute reprints for Governmental purposes
# notwithstanding any copyright notation thereon.
# 
# The views and conclusions contained herein are those of the authors and
# should not be interpreted as necessarily representing the official policies
# or endorsements, either expressed or implied, of the U.S. Government.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
# 
# @license GPL-3.0-or-later <https://spdx.org/licenses/GPL-3.0-or-later>
#===============================================================================
include(ExternalProject)

set_property (DIRECTORY PROPERTY EP_BASE Dependencies)
set (SUBMODULES_DIR ${PROJECT_SOURCE_DIR})
set (DEPENDENCIES)

set(INSTALL_DIR ${CMAKE_BINARY_DIR}/external)

list (APPEND DEPENDENCIES LibAFL_legacy)
ExternalProject_add(LibAFL_legacy
    SOURCE_DIR ${SUBMODULES_DIR}/LibAFL-legacy
    BUILD_IN_SOURCE 1
    BUILD_COMMAND make libafl.so
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ${PROJECT_SOURCE_DIR}/cmake/install-LibAFL-legacy ${PROJECT_SOURCE_DIR} ${INSTALL_DIR}
    # BUILD_ALWAYS 1
)

list (APPEND DEPENDENCIES AFLplusplus)
ExternalProject_add(AFLplusplus
    SOURCE_DIR ${SUBMODULES_DIR}/AFLplusplus
    BUILD_IN_SOURCE 1
    BUILD_COMMAND cp -f ${PROJECT_SOURCE_DIR}/cmake/AFLplusplus_config.h ${SUBMODULES_DIR}/AFLplusplus/include/config.h && git diff -U0 include/config.h && NO_NYX=1 AFL_MAP_SIZE=65536 CFLAGS="-fno-inline-small-functions" make source-only
    CONFIGURE_COMMAND make -C ${SUBMODULES_DIR}/AFLplusplus/custom_mutators/radamsa
    INSTALL_COMMAND ${PROJECT_SOURCE_DIR}/cmake/install-AFLplusplus ${PROJECT_SOURCE_DIR} ${INSTALL_DIR}
    # BUILD_ALWAYS 1
)

list (APPEND DEPENDENCIES YAML_CPP)
ExternalProject_add(YAML_CPP
    SOURCE_DIR ${SUBMODULES_DIR}/yaml-cpp
    CONFIGURE_COMMAND cmake 
        -DBUILD_SHARED_LIBS=ON 
        -DYAML_CPP_INSTALL=ON 
        -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
        ${SUBMODULES_DIR}/yaml-cpp
    INSTALL_COMMAND make install
    # BUILD_ALWAYS 1
)    

list (APPEND DEPENDENCIES PLOG)
ExternalProject_add(PLOG
    SOURCE_DIR ${SUBMODULES_DIR}/plog
    INSTALL_COMMAND ${PROJECT_SOURCE_DIR}/cmake/install-plog ${PROJECT_SOURCE_DIR} ${INSTALL_DIR}
    # BUILD_ALWAYS 1
)    

list (APPEND DEPENDENCIES GTEST)
ExternalProject_add(GTEST
    SOURCE_DIR ${SUBMODULES_DIR}/googletest
    CONFIGURE_COMMAND cmake 
        -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
        ${SUBMODULES_DIR}/googletest
    INSTALL_COMMAND make install
    # BUILD_ALWAYS 1
)
