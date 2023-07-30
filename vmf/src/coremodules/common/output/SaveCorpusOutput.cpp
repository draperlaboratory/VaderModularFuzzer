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
#include "SaveCorpusOutput.hpp"
#include "VaderUtil.hpp"
#include <string.h>
#include <limits.h> //for PATH_MAX
#include <algorithm>


using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(SaveCorpusOutput);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* SaveCorpusOutput::build(std::string name)
{
    return new SaveCorpusOutput(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void SaveCorpusOutput::init(ConfigInterface& config)
{
    std::string outputDir = config.getOutputDir();
    std::string fdir = outputDir + "/testcases";
    VaderUtil::createDirectory(fdir.c_str());

    std::vector<std::string> defaultTags = {"CRASHED","HUNG"};
    tagNames = config.getStringVectorParam(getModuleName(),"tagsToSave", defaultTags);
    numTags = tagNames.size();

    //Tag based directories are created based on the tags of interest
    for(int i=0; i<numTags; i++)
    {
        std::string name = tagNames[i];
        transform(name.begin(), name.end(), name.begin(), ::tolower);
        std::string dirName = fdir + "/" + name;
        VaderUtil::createDirectory(dirName.c_str());
        tagDirectories.push_back(dirName);
    }

    //Formatted and Unique are always created
    fdirFormatted = fdir + "/formatted";
    VaderUtil::createDirectory(fdirFormatted.c_str());
    fdirUnique = fdir + "/unique";
    VaderUtil::createDirectory(fdirUnique.c_str());
}

/**
 * @brief Construct a new SaveCorpusOutput module
 * 
 * @param name 
 */
SaveCorpusOutput::SaveCorpusOutput(std::string name):
    OutputModule(name)
{

}

/**
 * @brief Destructor
 * 
 */
SaveCorpusOutput::~SaveCorpusOutput()
{

}

/**
 * @brief Registers the keys and tags for this module
 * This module needs to read:
 * "CRASHED": whether or not a module has crashed
 * "TEST_CASE": the test case for a module
 * 
 * @param registry 
 */
void SaveCorpusOutput::registerStorageNeeds(StorageRegistry& registry)
{
    for(int i=0; i<numTags; i++)
    {
        int handle = registry.registerTag(tagNames[i], StorageRegistry::READ_ONLY);
        tagHandles.push_back(handle);
    }
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    testCaseFormattedKey = registry.registerKey("TEST_CASE_FORMATTED", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);

}

/**
 * @brief Writes all of the new entries with the "CRASHED" tag to disk
 * 
 * Only the binary test case is written to disk
 * 
 * @param storage 
 */
void SaveCorpusOutput::run(StorageModule& storage)
{
    //Save any tagged new entries
    int numHandles = tagHandles.size();
    for(int i=0; i<numHandles; i++)
    {
        int handle = tagHandles[i];
        std::unique_ptr<Iterator> newTaggedEntries = storage.getNewEntriesByTag(handle);
        while(newTaggedEntries->hasNext())
        {
            StorageEntry* nextEntry = newTaggedEntries->getNext();
            outputTestCase(nextEntry, tagDirectories[i]);
        }

    }

    std::unique_ptr<Iterator> interestingEntries = storage.getNewEntriesThatWillBeSaved();
    while(interestingEntries->hasNext())
    {
        StorageEntry* nextEntry = interestingEntries->getNext();
        outputTestCase(nextEntry, fdirUnique);

        //Check for a formatted version of the test case
        //If there is one, write a second copy of the file with the formatted content
        int formattedSize = nextEntry->getBufferSize(testCaseFormattedKey);
        if(formattedSize > 0)
        {
            char* buffer = nextEntry->getBufferPointer(testCaseFormattedKey);
            std::string filename = std::to_string(nextEntry->getID()) + "_FORMATTED";
            VaderUtil::writeBufferToFile(fdirFormatted, filename, buffer, formattedSize);
        }
    }

}

/**
 * @brief Helper method to output a test case
 * This method simply outputs the test case to a file on disk.  
 * 
 * @param entry the storage entry to output
 * @param dir the directory to output to
 */
void SaveCorpusOutput::outputTestCase(StorageEntry* entry, std::string dir)
{
    int size = entry->getBufferSize(testCaseKey);
    char* buffer = entry->getBufferPointer(testCaseKey);
    unsigned long id = entry->getID();

    // create a file name with id
    std::string filename = std::to_string(id);
    VaderUtil::writeBufferToFile(dir, filename, buffer, size);
}


