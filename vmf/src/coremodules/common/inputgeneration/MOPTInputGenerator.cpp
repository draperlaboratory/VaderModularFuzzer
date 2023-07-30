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
#include "MOPTInputGenerator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "VaderUtil.hpp"

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(MOPTInputGenerator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* MOPTInputGenerator::build(std::string name)
{
    return new MOPTInputGenerator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void MOPTInputGenerator::init(ConfigInterface& config)
{
    mutators = MutatorModule::getMutatorSubmodules(config,getModuleName());
    int size = mutators.size();
    if(0 == size)
    {
        throw RuntimeException("MOPTInputGenerator must be configured with at least one child mutator",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    for(int i=0; i<size; i++)
    {
        mutatorStats.push_back(0); //Push back a stats entry for each new mutator
        mutatorStatsTotalTestCases.push_back(0);
    }


    int numSwarms = config.getIntParam(getModuleName(), "numSwarms", 5);
    int pilotPeriod = config.getIntParam(getModuleName(), "pilotPeriodLength", 50000);
    int corePeriod = config.getIntParam(getModuleName(), "corePeriodLength", 500000);
    double pMin = config.getFloatParam(getModuleName(), "pMin", 0);
    
    testCasesRan = 0;
    
    // Create a new MOPT object. We must provide it with our mutators and the desired
    // number of swarms and period lengths.
    LOG_INFO << "MOPT swarms: " << numSwarms;
    LOG_INFO << "pilotPeriodLength: " << pilotPeriod;
    LOG_INFO << "corePeriodLength: " << corePeriod;
    LOG_INFO << "pMin: " << pMin;

    mopt = new MOPT(&mutators, numSwarms, pilotPeriod, corePeriod, pMin);
}

/**
 * @brief Construct a new Genetic Algorithm Input Generator module
 * 
 * @param name the name of the module
 */
MOPTInputGenerator::MOPTInputGenerator(std::string name) :
    InputGeneratorModule(name)
{

}


MOPTInputGenerator::~MOPTInputGenerator()
{
    delete mopt;
}


void MOPTInputGenerator::registerStorageNeeds(StorageRegistry& registry)
{
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
    mutatorIdKey = registry.registerKey("MUTATOR_ID", StorageRegistry::INT, StorageRegistry::READ_WRITE);
}


void MOPTInputGenerator::addNewTestCases(StorageModule& storage)
{

    StorageEntry* baseTestCase = selectBaseEntry(storage);

    if(nullptr != baseTestCase)
    {
	// Generate N testcases per call to AddNewTestCases()
        for(size_t i=0; i< 32; i++)
        {
	        int pickedMutator = mopt -> pickMutator();
	        StorageEntry* newEntry = mutators[pickedMutator]->createTestCase(storage, baseTestCase);
            newEntry->setValue(mutatorIdKey, pickedMutator + 1); //The id is simply the index into the mutators vector plus 1
	        mopt->updateExecCount(pickedMutator);
	        testCasesRan++;
        }
    }
}

void MOPTInputGenerator::evaluateTestCaseResults(StorageModule& storage)
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
}

/**
 * @brief Helper method to select the base entry to mutate
 * 
 * This implementation uses a weighted random selection that favors entries with lower indices
 * 
 * @param storage the storage module 
 * @return StorageEntry* the base entry to use
 */
StorageEntry* MOPTInputGenerator::selectBaseEntry(StorageModule& storage)
{
    StorageEntry* baseTestCase = nullptr;
    std::unique_ptr<Iterator> entries;
   
    //Use only the entries in the corpus that ran normally
    entries = storage.getEntriesByTag(normalTag);

    int maxIndex = entries->getSize();
    if(0 == maxIndex) {
        //This should only occur on the first run.  It either indicates that we are not receiving feedback
        //from the executor, causing it to never flag any entries to be saved (and tagged as "RAN_SUCCESSFULLY"), 
        //or vader was configured without a seed generator, so there are no initial test cases to run.
        throw RuntimeException("No executed test cases in storage.  Either something is wrong with the executor feedback, or there is no seed generator.",
                            RuntimeException::USAGE_ERROR);
    }

    int randIndex = VaderUtil::selectWeightedRandomValue(0, maxIndex);
    baseTestCase = entries->setIndexTo(randIndex);
    return baseTestCase;
}

