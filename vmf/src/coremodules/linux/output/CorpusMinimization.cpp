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
#include "CorpusMinimization.hpp"
#include "VaderUtil.hpp"
#include "Logging.hpp"
#include <stdlib.h>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(CorpusMinimization);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* CorpusMinimization::build(std::string name)
{
    return new CorpusMinimization(name);
}

/**
 * @brief Initialization method
 * Finds an executor instance to run testcases with and resets state.
 * 
 * @param config 
 */
void CorpusMinimization::init(ConfigInterface& config)
{
    minutesBetweenMinimization = config.getIntParam(getModuleName(), "frequencyInMinutes", 30);
    minimizeOnShutdown = config.getBoolParam(getModuleName(), "minimizeOnShutdown", true);

    ExecutorModule* execModule = ExecutorModule::getExecutorSubmodule(config,getModuleName());
    executor = AFLExecutor::castTo(execModule);

    formerCorpusSize = 0;
    mapSize = 0;

    //Configure Output Directory to write Minimized Corpus to
    std::string baseDir = config.getOutputDir();
    std::string testCaseDir = baseDir + "/testcases";
    VaderUtil::createDirectory(testCaseDir.c_str());
    outDir = testCaseDir + "/minimized";
}

/**
 * @brief Construct a new CorpusMinimization module
 * 
 * @param name 
 */
CorpusMinimization::CorpusMinimization(std::string name):
    OutputModule(name)
{

}

/**
 * @brief Destructor
 * 
 */
CorpusMinimization::~CorpusMinimization()
{
    //Free the coverage map if it has been allocated
    if(mapSize > 0)
    {
        delete[] corpusCoverage;
    }

}

void CorpusMinimization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    testCaseFormattedKey = registry.registerKey("TEST_CASE_FORMATTED", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
}

OutputModule::ScheduleTypeEnum CorpusMinimization::getDesiredScheduleType()
{
    if(minutesBetweenMinimization != 0)
    {
        return CALL_ON_NUM_SECONDS;
    }
    else
    {
        return CALL_ONLY_ON_SHUTDOWN;
    }
}

int CorpusMinimization::getDesiredScheduleRate()
{
    //Convert minutes to seconds
    //Note: This parameter is ignored when schedule type is CALL_ONLY_ON_SHUTDOWN
    return minutesBetweenMinimization * 60;
}

/**
 * @brief Minimize corpus for all entries tagged as RAN_SUCCESSFULLY
 * Run all testcases and figure which are not contributing to coverage.
 * Testcases that do not contribute are deleted, allowing fuzzer to focus on useful cases.
 * @param storage 
 */
void CorpusMinimization::run(StorageModule& storage)
{
    int corpusSize = storage.getEntriesByTag(normalTag)->getSize();
    if(corpusSize > formerCorpusSize)
    {
        //Only minimize if we have any new test cases to minimize with
        int numRemoved = minimizeCorpus(storage);
        formerCorpusSize = corpusSize - numRemoved;
    }
}

void CorpusMinimization::shutdown(StorageModule& storage)
{
    if(minimizeOnShutdown)
    {
        minimizeCorpus(storage);
    }
}

/**
 * @brief Helper method to perform corpus minimization
 * 
 * This removes test cases that do not contribute to coverage.
 * Storage is modified by this method.
 * 
 * @param storage the storage module
 * @return int the number of test cases removed from storage
 */
int CorpusMinimization::minimizeCorpus(StorageModule& storage)
{
    //Clear the old output directory
    fs::remove_all(outDir);
    VaderUtil::createDirectory(outDir.c_str());

    std::unique_ptr<Iterator> allEntries = storage.getEntriesByTag(normalTag);
    LOG_INFO << "Corpus Minimization running, current number of testcases: " << allEntries -> getSize();

    //If the coverage map has not yet been created, create it
    if(0 == mapSize)
    {
        mapSize = executor -> getCoverageSize();
        corpusCoverage = new char[mapSize];
    }

    //Set every value in the coverage map to 0
    memset(corpusCoverage, 0, mapSize);

    // Run all testcases and add their coverage onto corpusCoverage.
    // They are already sorted by fitness, so we are preferring ones with higher fitness (smaller, faster, etc)
    int testCasesDeleted = 0;
    int coveredBytes = 0;      
    while(allEntries->hasNext())
    {
        // Run testcase and get coverage data
        // Use the formatted version of the test case if one is available
        StorageEntry* e = allEntries->getNext();
        int size = e -> getBufferSize(testCaseFormattedKey);
        char * buffer = nullptr;
        if(size > 0)
        {
            //Use formatted test case
            buffer = e->getBufferPointer(testCaseFormattedKey);
        }
        else
        {
            //Use original, unformatted version of test case
            size = e -> getBufferSize(testCaseKey);
            buffer = e->getBufferPointer(testCaseKey);
        }
        executor -> runTestCase(buffer, size);

        // Compare coverage to corpusCoverage
        char * coverage = executor -> getCoverageBitsClassified();
        int uniqueBytes = 0;
        for (int i = 0; i < mapSize; i++)
        {
        
            if (corpusCoverage[i] == 0 && coverage[i] != 0)
                coveredBytes++;

            // A new hitcount class on an already covered byte still counts as contributing coverage
            if (corpusCoverage[i] != (corpusCoverage[i] | coverage[i]))
            {
                uniqueBytes++;
                corpusCoverage[i] = corpusCoverage[i] | coverage[i];
            }
        }

        // If this testcase did not contribute to corpusCoverage, then mark for deletion
        if (uniqueBytes == 0)
        {
            testCasesDeleted++;
            storage.removeEntry(e);
        }
        else
        {
            //Otherwise, archive a copy in the minset directory
            std::string filename = std::to_string(e->getID());  
            VaderUtil::writeBufferToFile(outDir, filename, buffer, size);
        }

    }

    LOG_INFO << "Corpus Minimization culled " << testCasesDeleted << " testcases with no coverage improvement.";
    LOG_INFO << "---------------------------------";    

    return testCasesDeleted;
}

