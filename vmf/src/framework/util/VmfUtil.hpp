/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (only) as 
 * published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 * @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
 * ===========================================================================*/
#pragma once
#include "StorageModule.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

#include <chrono>
#include <filesystem>
#include <fstream> // for filestream
#include <random>
#include <stdio.h>
#include <string>


namespace vmf
{
/**
 * @brief Common utility functions for VMF
 * 
 */
class VmfUtil
{
public:
    static uint64_t getCurTime(void);
    static uint64_t getCurTimeSecs(void);
  
    static void createDirectory(const char* path);
    static bool directoryExists(std::string dir);
    static int createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory);
    static void writeBufferToFile(std::string baseDir, std::string fileName, const char* buffer, int size);
    static std::string getExecutablePath();
    static int selectWeightedRandomValue(int min, int max);
    static size_t hashBuffer(char * buff, int len);
};
}
