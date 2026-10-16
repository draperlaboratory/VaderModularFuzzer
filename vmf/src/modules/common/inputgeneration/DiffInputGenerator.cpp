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
#include "DiffInputGenerator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "StorageRegistry.hpp"
#include "VmfUtil.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(DiffInputGenerator);

Module* DiffInputGenerator::build(std::string name)
{
    return new DiffInputGenerator(name);
}

void DiffInputGenerator::init(ConfigInterface& config)
{
    mutators = MutatorModule::getMutatorSubmodules(config,getModuleName());
    int size = (int)mutators.size();
    if(0 == size)
    {
        throw RuntimeException("DiffInputGenerator must be configured with at least one child mutator",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    for(int i=0; i<size; i++)
    {
        mutatorStats.push_back(0); //Push back a stats entry for each new mutator
        mutatorStatsTotalTestCases.push_back(0);
    }

    executors = ExecutorModule::getExecutorSubmodules(config, 
        config.getSuperModule(getModuleName())->getModuleName());

    int numSwarms = config.getIntParam(getModuleName(), "numSwarms", 5);
    int pilotPeriod = config.getIntParam(getModuleName(), "pilotPeriodLength", 50000);
    int corePeriod = config.getIntParam(getModuleName(), "corePeriodLength", 500000);
    double pMin = config.getFloatParam(getModuleName(), "pMin", 0);
    
    testCasesRan = 0;
    batchNum = 0;
    
    // Create a new MOPT object. We must provide it with our mutators and the desired
    // number of swarms and period lengths.
    LOG_INFO << "MOPT swarms: " << numSwarms;
    LOG_INFO << "pilotPeriodLength: " << pilotPeriod;
    LOG_INFO << "corePeriodLength: " << corePeriod;
    LOG_INFO << "pMin: " << pMin;

    mopt = new MOPT(&mutators, numSwarms, pilotPeriod, corePeriod, pMin);
    batchNumIdKey = 0;
}

DiffInputGenerator::DiffInputGenerator(std::string name) :
    InputGeneratorModule(name)
{

}


DiffInputGenerator::~DiffInputGenerator()
{
    delete mopt;
}


void DiffInputGenerator::registerStorageNeeds(StorageRegistry& registry)
{
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);

    for(auto const& e : executors)
    {
        executorIdTags.emplace_back(registry.registerTag(e->getModuleName(), StorageRegistry::WRITE_ONLY));
    }

    moptMutatorIdKey = registry.registerIntKey("MOPT_MUTATOR_ID", StorageRegistry::READ_WRITE, -1);
    mutatorIdKey = registry.registerIntKey("MUTATOR_ID", StorageRegistry::WRITE_ONLY, 1);
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
    batchNumIdKey = registry.registerU64Key("ENTRY_BATCH_NUM", StorageRegistry::WRITE_ONLY, 0);
}


void DiffInputGenerator::addNewTestCases(StorageModule& storage)
{

    StorageEntry* baseTestCase = selectBaseEntry(storage);

    if(nullptr != baseTestCase)
    {
        // Generate N testcases per call to AddNewTestCases()
        for(size_t i=0; i< 32; i++)
        {
            int pickedMutator = mopt -> pickMutator();
            MutatorModule* mutator = mutators[pickedMutator];
            StorageEntry* commonEntry = storage.createNewEntry();
            mutator->mutateTestCase(storage, baseTestCase, commonEntry, testCaseKey);

            // Copy the old buffer before modifying it for safety
            char* oldBuff = commonEntry->getBufferPointer(testCaseKey);
            int newSize = commonEntry->getBufferSize(testCaseKey);
            
            if(executorIdTags.size() > 1)
            {
                for(size_t i=1; i<executorIdTags.size(); i++)
                {
                    int tag = executorIdTags[i];

                    // create a copy of the base entry to uniquely tag for each subsquent executor
                    StorageEntry* newEntry = storage.createNewEntry();
                    char* newBuff = newEntry->allocateBuffer(testCaseKey, newSize);

                    memcpy((void*)newBuff, (void*)oldBuff, newSize);
                
                    newEntry->setValue(moptMutatorIdKey, pickedMutator + 1); // Id is the index into the mutators vector plus 1
                    newEntry->setValue(mutatorIdKey, mutator->getID());
                    newEntry->setValue(batchNumIdKey, batchNum);
                    newEntry->addTag(tag);
                    mopt->updateExecCount(pickedMutator);
                    testCasesRan++;
                }
            }
            // Edit the commonEntry last, based on a gut feeling
            commonEntry->setValue(moptMutatorIdKey, pickedMutator + 1);
            commonEntry->setValue(mutatorIdKey, mutator->getID());
            commonEntry->setValue(batchNumIdKey, batchNum); 
            commonEntry->addTag(executorIdTags[0]);
            mopt->updateExecCount(pickedMutator);
            testCasesRan++;
            batchNum++;
        }
    }
}

bool DiffInputGenerator::examineTestCaseResults(StorageModule& storage)
{

    std::unique_ptr<Iterator> interestingEntries = storage.getNewEntriesThatWillBeSaved();

    while(interestingEntries->hasNext())
    {
        StorageEntry* entry = interestingEntries->getNext();
        int id = entry->getIntValue(mutatorIdKey);
        if(id > 0 && id <= (int)mutatorStats.size())
        {
            int mutator = id - 1;
            mopt->updateFindingsCount(mutator);
        }
    }

    mopt -> ranTestCases(testCasesRan, true);
    testCasesRan = 0;

    return false; //This input generator is never "complete"
}


StorageEntry* DiffInputGenerator::selectBaseEntry(StorageModule& storage)
{
    StorageEntry* baseTestCase = nullptr;
    std::unique_ptr<Iterator> entries;
   
    //Use only the entries in the corpus that ran normally
    entries = storage.getSavedEntriesByTag(normalTag);

    int maxIndex = entries->getSize();
    if(0 == maxIndex) {
        //This should only occur on the first run.  It either indicates that we are not receiving feedback
        //from the executor, causing it to never flag any entries to be saved (and tagged as "RAN_SUCCESSFULLY"), 
        //or VMF was configured without a seed generator, so there are no initial test cases to run.
        throw RuntimeException("No executed test cases in storage.  Either something is wrong with the executor feedback, or there is no seed generator.",
                            RuntimeException::USAGE_ERROR);
    }

    int randIndex = VmfUtil::selectWeightedRandomValue(0, maxIndex);
    baseTestCase = entries->setIndexTo(randIndex);
    return baseTestCase;
}

