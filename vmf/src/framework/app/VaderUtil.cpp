/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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
#include "VaderUtil.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include <experimental/filesystem>
#include <random>

//#include <sys/stat.h> // for mkdir
//#include <cstring> // for strerror
#if defined (_WIN32)
    #include "dirent.h"
#else
    #include <dirent.h> // for opendir
#endif
#include <fstream> // for filestream
#include <stdio.h>

#if !defined(_WIN32)
    //Linux specific headers
    #include <libgen.h>         // dirname
    #include <unistd.h>         // readlink
    #include <linux/limits.h>   // PATH_MAX
#else
    //Windows headers
    #include <Shlwapi.h>
#endif

using namespace vader;

/**
 * @brief Creates a directory if it does not already exist
 * 
 * @param path the path to create (as char[])
 * @throws RuntimeException if unable to create the directory
 */
void VaderUtil::createDirectory(const char* path)
{
    namespace fs = std::experimental::filesystem;
    if (!fs::exists(path)) { // Check if src folder exists
        bool created = fs::create_directories(path); // create src folder
        if(!created)
        {
            throw RuntimeException("Unable to create directory, check permissions", 
                RuntimeException::USAGE_ERROR);
        }
    }
}

/**
 * @brief Helper method to check if a directory exists or not
 * 
 * @param dir the directory
 * @return true if it exists
 * @return false false otherwise
 */
bool VaderUtil::directoryExists(std::string dir)
{
    namespace fs = std::experimental::filesystem;
    bool exists = fs::exists(dir);
    return exists;
}



/**
 * @brief Helper method to create one new test case per file in the directory
 * 
 * The contents of each file will be used to fill the "TEST_CASE" buffer
 * 
 * @param storage the storage object
 * @param testCaseKey the handle for the "TEST_CASE" field
 * @param directory the directory to read
 */
void VaderUtil::createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory)
{
    if(directory.back() != '/')
    {   directory.append("/"); }

    const char* dirPath = directory.c_str();
    DIR* dirp = opendir(dirPath);
    if(nullptr == dirp)
    {
        LOG_ERROR << "Unable to open input directory: " << dirPath;
        throw RuntimeException("Unable to open input directory", RuntimeException::USAGE_ERROR);
    }

    struct dirent* dp;
    while ((dp = readdir(dirp)) != NULL) 
    {
      	char fpath[512];
      	sprintf(fpath, "%s", dirPath);
      	strcat(fpath, dp->d_name);

        if((strcmp(dp->d_name, "..") != 0)
            && (strcmp(dp->d_name, ".") != 0))
        {
            // open and read next file into buffer
            std::ifstream inFile;
            inFile.open(fpath, std::ifstream::binary);
            if (inFile.is_open()) 
            {
                // get size
                inFile.seekg(0, inFile.end);
                int size = inFile.tellg();

		// files of size 0 are ignored
		if (0 == size)
		{
		    LOG_INFO << "Warning: ignoring input file of size 0.";
		    continue;
		}

                inFile.seekg(0, inFile.beg);

                // store file contents
                StorageEntry* newEntry = storage.createNewEntry();
                char* buff = newEntry->allocateBuffer(testCaseKey, size);
                inFile.read(buff, size);

            }
            else
            {
                std::string name(fpath);
                LOG_ERROR << "Unable to open input file: " << fpath;
            }
            inFile.close();
        }
    }
    closedir(dirp);
}

/**
 * @brief Writes a buffer to the specified file
 * 
 * The slash between the baseDir and the fileName will be added automatically
 * 
 * @param baseDir the base directory to write to
 * @param fileName the file name
 * @param buffer the buffer pointer
 * @param size the size (in bytes)
 */
void VaderUtil::writeBufferToFile(std::string baseDir, std::string fileName, char* buffer, int size)
{
    std::string path = baseDir + "/" + fileName;
    std::ofstream outFile;
    outFile.open (path.c_str());
    if(outFile.is_open())
    {
        outFile.write(buffer, size);
    }
    outFile.close();
}

/**
 * @brief Helper method to retrieve the path of the currently running vmf executable
 * 
 * @return std::string the path to the executable
 */
std::string VaderUtil::getExecutablePath()
{
    #if !defined(_WIN32)
        char result[PATH_MAX];
        const char *path;

        ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
        if (count > 0) {
            result[count] = 0;
            path = dirname(result);
        }
        std::string val(path);
        return val;

    #else
        //TODO(VADER-720): This does not work on windows
        //TCHAR result[MAX_PATH];
        //DWORD length = GetModuleFileName( NULL, result, MAX_PATH );
        //PathCchRemoveFileSpec(result, MAX_PATH);
        //std::string val(result);
        std::string val = "./";
        return val;
    #endif
}

/**
 * @brief Helper method to select a weighted random value
 * The selected value will skew more heavily towards lower values.
 * This implementation use a simple two step algorithm:
 * 1.	Pick a random max_bound between min and max-1
 * 2.	Pick a random index between min and max_bound
 * 
 * @param min the minimum value (inclusive)
 * @param max the maximum value (exclusive)
 * @return int 
 */
int VaderUtil::selectWeightedRandomValue(int min, int max)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> bounds(min, max-1);
    int maxBound = bounds(gen);
    std::uniform_int_distribution<> index(min, maxBound);
    int rand = index(gen);

    return rand;
}
