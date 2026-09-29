/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
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
#include "SaveCorpusOutput.hpp"
#include "VmfUtil.hpp"
#include <string.h>
#include <limits.h> //for PATH_MAX
#include <algorithm>
#include "yaml-cpp/yaml.h" //for emitting YAML for metadata


using namespace vmf;

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
    VmfUtil::createDirectory(fdir.c_str());

    std::vector<std::string> defaultTags = {"CRASHED","HUNG"};
    tagNames = config.getStringVectorParam(getModuleName(),"tagsToSave", defaultTags);
    numTags = (int) tagNames.size();

    //Tag based directories are created based on the tags of interest
    for(int i=0; i<numTags; i++)
    {
        std::string name = tagNames[i];
        transform(name.begin(), name.end(), name.begin(), ::tolower);
        std::string dirName = fdir + "/" + name;
        VmfUtil::createDirectory(dirName.c_str());
        tagDirectories.push_back(dirName);
    }

    //Unique is always created
    fdirUnique = fdir + "/unique";
    LOG_INFO << "Creating output directory: " << fdirUnique;
    VmfUtil::createDirectory(fdirUnique.c_str());

    //Output mutator IDs used to generate each test case
    recordTestMetadata = config.getBoolParam(getModuleName(), "recordTestMetadata", false);

    //Save reference to config
    this->config = &config;
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
    mutatorIdKey = registry.registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    testcaseParentIdKey = registry.registerKey("PARENT_ID", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    generationKey = registry.registerKey("GENERATION", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    numChildrenKey = registry.registerKey("NUM_CHILDREN", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    timestampKey = registry.registerKey("EXEC_TIMESTAMP_US", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    execTimeKey = registry.registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::READ_ONLY);

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
    int numHandles = (int) tagHandles.size();

    std::unique_ptr<Iterator> interestingEntries = storage.getNewEntriesThatWillBeSaved();
    while(interestingEntries->hasNext())
    {
        StorageEntry* nextEntry = interestingEntries->getNext();
        outputTestCase(nextEntry, fdirUnique);

        //Now check to see if this entry has any of the tags of interest
        for(int i=0; i<numHandles; i++)
        {  
            int handle = tagHandles[i];
            if(nextEntry->hasTag(handle))
            {
                outputTestCase(nextEntry, tagDirectories[i]);
            }
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

    // Output test case buffer
    // create a file name with id
    std::string filename = std::to_string(id);
    VmfUtil::writeBufferToFile(dir, filename, buffer, size);

    // Output test case metadata
    /* Create a separate file for test case metadata */
    if (recordTestMetadata) {        
        outputMetadata(filename, id, entry, dir);
    }
}

void SaveCorpusOutput::outputMetadata(std::string filename, unsigned long id, vmf::StorageEntry *entry, std::string &dir)
{
    YAML::Emitter out;
    out << YAML::BeginMap;
    filename += "_metadata";

    /* Get mutator information */
    int mutatorId = entry->getIntValue(mutatorIdKey);
    if (mutatorId == -1)
        out << YAML::Key << "mutator" << YAML::Value << "<NULL>";
    else
        out << YAML::Key << "mutator" << YAML::Value << config->getModuleName(mutatorId);
    
    /* Get test case parent information */
    out << YAML::Key << "parent" << YAML::Value << entry->getUIntValue(testcaseParentIdKey);

    /* Get test case generation information */
    out << YAML::Key << "generation" << YAML::Value << entry->getUIntValue(generationKey);

    
    /* Get test case generation information */
    out << YAML::Key << "timestamp" << YAML::Value << entry->getUIntValue(timestampKey);

    out << YAML::Key << "exec_time" << YAML::Value << entry->getUIntValue(execTimeKey);
 
    out << YAML::EndMap;
    VmfUtil::writeBufferToFile(dir, filename, out.c_str(), out.size());
}

