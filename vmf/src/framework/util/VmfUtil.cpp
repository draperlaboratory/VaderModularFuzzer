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
#include "VmfUtil.hpp"
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
    return createNewTestCasesFromDirImpl(storage, testCaseKey, directory, -1, -1);
}

/**
 * @brief Helper method to create one new test case per file in the directory (and optionally write extra data)
 *
 * The contents of each file will be used to fill the "TEST_CASE" buffer.  
 * If the filenameKey is not -1, then the filename will be written to each test case.
 * Similarly, if the serverTestCaseTag is not -1, the the "SERVER_TC" tag will be written to each test case
 *
 * @param storage the storage object
 * @param testCaseKey the handle for the "TEST_CASE" field
 * @param directory the directory to read
 * @param filenameKey the handle for the filename field
 * @param serverTestCaseTag the tag for test cases coming from the server
 * @returns the number of new test cases that were created
 */
int VmfUtil::createNewTestCasesFromDir(StorageModule& storage, int testCaseKey, std::string directory, int filenameKey, int serverTestCaseTag)
{
    return createNewTestCasesFromDirImpl(storage, testCaseKey, directory, filenameKey, serverTestCaseTag);
}

/**
 * @brief Implementation method for both version of createNewTestCasesFromDir
 * 
 * @param storage the storage object
 * @param testCaseKey the handle for the "TEST_CASE" field
 * @param directory the directory to read
 * @param filenameKey the handle for the filename field (or -1 if not used)
 * @param serverTestCaseTag the tag for test cases that came from the server (or -1 if not used)
 * @return the number of new test cases that were created
 */
int VmfUtil::createNewTestCasesFromDirImpl(StorageModule& storage, int testCaseKey, std::string directory, int filenameKey, int serverTestCaseTag)
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
                LOG_WARNING << "Warning: " << file.path() << " doesn't exist. Skipping";
                continue;
            }

            if (!fs::is_regular_file(file))
            {
                LOG_WARNING << "Warning: " << file.path() << " is not a regular file. Skipping.";
                continue;
            }

            filesize = fs::file_size(file);

            if (static_cast<uintmax_t>(1) > filesize)
            {
                LOG_WARNING << "Warning: " << file.path() << " has size 0. Skipping.";
                continue;
            }
        }
        catch(const std::exception& e)
        {
            LOG_WARNING << "Warning: File checks for " << file.path() << "returned error: " << e.what();

            throw RuntimeException("Unable to open input file", RuntimeException::UNEXPECTED_ERROR);

        }
	    files.insert(std::make_pair(file.path(), file));
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
        char* buff = newEntry->allocateBuffer(testCaseKey, filesize);
        inFile.read(buff, filesize);
        newTestCaseCount++;

        if(-1 != filenameKey)
        {
            std::string name = file.path().filename();
            char* nameBuff = newEntry->allocateBuffer(filenameKey, name.length());
            name.copy(nameBuff,name.length());
        }
        if(-1 != serverTestCaseTag)
        {
            newEntry->addTag(serverTestCaseTag);
        }
        

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
std::string VmfUtil::getExecutablePath()
{
    #if !defined(_WIN32)
        char result[PATH_MAX];
        const char *path = nullptr;

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
int VmfUtil::selectWeightedRandomValue(int min, int max)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> bounds(min, max-1);
    int maxBound = bounds(gen);
    std::uniform_int_distribution<> index(min, maxBound);
    int rand = index(gen);

    return rand;
}

/**
 * @brief Helper method to retrieve the current time in microseconds
 * 
 * @return uint64_t the time (us)
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
 * @brief Utility method to unzip the specified file using the command line unzip utility
 * 
 * This method does require an unzip utility to be installed.
 * 
 * @param zipFilePath the path to the zip file to unzip
 * @param outputDir the output directory to write to (the directory will be created if it does not exist)
 * @return true if unzip was successful, false otherwise
 */
bool VmfUtil::commandLineUnzip(std::string zipFilePath, std::string outputDir)
{
    bool success = false;
    //TODO(Windows Support): This is a linux only implementation
    //Example usage:
    // unzip -q ../ZIPAUTOGEN_TEST.zip -d ~/ziptest/out2

    //Create the output directory if it doesn't exist
    if(!directoryExists(outputDir))
    {
        createDirectory(outputDir.c_str());
    }

    //Unzip the file
    std::string unzipCmd = "unzip -q " + zipFilePath + " -d " + outputDir;
    if(system(unzipCmd.c_str())==0)
    {
        success = true;
    }
    else
    {
        LOG_ERROR << "Unable to unzip file using command;" << unzipCmd;
    }
    
    return success;
}

/**
 * @brief Utility method to zip up all the files in a directory (using the command line zip utility)
 * 
 * This method does require an zip utility to be installed.  The foldername will not be included
 * in the resulting zip file.
 * 
 * @param zipFilePath the path to the output zipfile
 * @param inputDir the input directory to read the files from
 * @return true if zip was successful, false otherwise
 */
bool VmfUtil::commandLineZip(std::string zipFilePath, std::string inputDir)
{
    bool success = false;
    //TODO(Windows Support): This is a linux only implementation
    //Example usage:
    // zip -r -j -q myzip2.zip ~/testing/*

    //Make sure the input directory exists
    if(directoryExists(inputDir))
    {
        std::string zipCmd = "zip -r -j -q " + zipFilePath + " " + inputDir + "/*";
        if(system(zipCmd.c_str())==0)
        {
            success = true;
        }
        else
        {
            LOG_ERROR << "Unable to unzip file using command;" << zipCmd;
        }
    }
    else
    {
        LOG_ERROR << "Zip input directory not found; " << inputDir;
    }

    return success;
}
