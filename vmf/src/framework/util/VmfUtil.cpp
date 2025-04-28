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
#include "VmfUtil.hpp"
#include "VmfRand.hpp"
#include "OSAPI.hpp"
#include <set>

using namespace vmf;
namespace fs = std::filesystem;

/**
 * @brief Creates a directory if it does not already exist
 *
 * @param path the path to create (as char[])
 * @throws RuntimeException if unable to create the directory
 */
void VmfUtil::createDirectory(const char* path)
{
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
bool VmfUtil::directoryExists(std::string dir)
{
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
 * @returns the number of new test cases that were created
 */
int VmfUtil::createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory)
{
    fs::path dirPath(directory);

    if (!fs::exists(dirPath) ||
        !fs::is_directory(dirPath))
    {
        LOG_ERROR << "Unable to open input directory: " << dirPath;
        throw RuntimeException("Unable to open input directory", RuntimeException::USAGE_ERROR);
    }

    int newTestCaseCount = 0;

    // Collect files in directory and sort them by path.
    // Sets are always sorted.
    std::set<std::pair<fs::path, fs::directory_entry>> files;
    for (const auto& file : fs::directory_iterator(dirPath))
    {
        uintmax_t filesize = static_cast<uintmax_t>(0);
        try
        {
            if (!fs::exists(file))
            {
                LOG_WARNING << "Warning: " << file.path().string() << " doesn't exist. Skipping";
                continue;
            }

            if (!fs::is_regular_file(file))
            {
                LOG_WARNING << "Warning: " << file.path().string() << " is not a regular file. Skipping.";
                continue;
            }

            filesize = fs::file_size(file);

            if (static_cast<uintmax_t>(1) > filesize)
            {
                LOG_WARNING << "Warning: " << file.path().string() << " has size 0. Skipping.";
                continue;
            }
        }
        catch(const std::exception& e)
        {
            LOG_WARNING << "Warning: File checks for " << file.path() << "returned error: " << e.what();

            throw RuntimeException("Unable to open input file", RuntimeException::UNEXPECTED_ERROR);

        }
        files.insert(std::make_pair(file.path().string(), file));
    }

    // Iterate over sorted files
    for (auto it : files)
    {
        fs::directory_entry file = it.second;

        uintmax_t filesize = static_cast<uintmax_t>(0);

        // open and read file into buffer
        filesize = fs::file_size(file);
        std::ifstream inFile;
        inFile.open(file.path(), std::ifstream::binary);

        // store file contents
        StorageEntry* newEntry = storage.createNewEntry();
        char* buff = newEntry->allocateBuffer(testCaseKey, (int)filesize);
        inFile.read(buff, filesize);
        newTestCaseCount++;

        inFile.close();
    }

    return newTestCaseCount;
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
void VmfUtil::writeBufferToFile(std::string baseDir, std::string fileName, const char* buffer, int size)
{
    std::string path = baseDir + "/" + fileName;
    std::ofstream outFile;
    outFile.open (path.c_str(), std::ios::binary);
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
std::string VmfUtil::getExecutablePath()
{
    return OSAPI::instance().getExecutablePath();
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
int VmfUtil::selectWeightedRandomValue(int min, int max)
{
    VmfRand* rand = VmfRand::getInstance();
    int maxBound = rand->randBetween(min, max -1);
    int index = rand->randBetween(min, maxBound);
    return index;
}

/**
 * @brief Helper method to retrieve the current time in microseconds
 * 
 * Note that the epoch of this time is unspecified, so it is appropriate for use
 * in timing how long something takes, but it may not be easily mappable to current
 * actual time.
 * 
 * @return uint64_t the timestamp (us)
 */
uint64_t VmfUtil::getCurTime() 
{
  auto time =
      std::chrono::high_resolution_clock::now().time_since_epoch();
  auto now_us =
    std::chrono::duration_cast<std::chrono::microseconds>(time).count();
  return now_us;
}

/**
 * @brief Helper method to retrieve the current UTC time in seconds
 * 
 * Use this version of the method for a UTC timestamp.  getCurTime()
 * is more appropriate for timing how long something takes to execute.
 * 
 * @return uint64_t the time (seconds)
 */
uint64_t VmfUtil::getCurTimeSecs(void)
{
  auto time =
      std::chrono::system_clock::now().time_since_epoch();
  auto now_us =
    std::chrono::duration_cast<std::chrono::seconds>(time).count();
  return now_us;
}

/**
 * @brief Utility method to hash a buffer. Uses the FNV-1 algorithm.
 *
 * @return size_t hash
 */
size_t VmfUtil::hashBuffer(char * buff, int len)
{
    size_t hash = 0xcbf29ce484222325;
    size_t prime = 1099511628211;
    for (int i = 0; i < len; i++)
    {
        hash = hash * prime;
        hash = hash ^ buff[i];
    }
    return hash;
}
