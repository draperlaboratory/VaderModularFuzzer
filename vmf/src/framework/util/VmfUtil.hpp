/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
 *  
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * Is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *  
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
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

#if !defined(_WIN32)
    //Linux specific headers
    #include <libgen.h>         // dirname
    #include <unistd.h>         // readlink
    #include <linux/limits.h>   // PATH_MAX
#else
    //Windows headers
    #include <Shlwapi.h>
#endif

#ifndef MIN
  #define MIN(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a < _b ? _a : _b;      \
                              \
    })

  #define MAX(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b;      \
                              \
    })

#endif


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
  
    static void createDirectory(const char* path);
    static bool directoryExists(std::string dir);
    static int createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory);
    static int createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory, int filenameKey, int serverTestCaseTag);
    static void writeBufferToFile(std::string baseDir, std::string fileName, const char* buffer, int size);
    static std::string getExecutablePath();
    static int selectWeightedRandomValue(int min, int max);
    static bool commandLineUnzip(std::string zipFilePath, std::string outputDir);
    static bool commandLineZip(std::string zipFilePath, std::string inputDir);
    
private:
    static int createNewTestCasesFromDirImpl(StorageModule& storage, int testCaseKey, std::string directory, int filenameKey, int serverTestCaseTag);
};
}
