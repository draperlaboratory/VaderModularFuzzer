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
#include "GeneticAlgorithmInputGenerator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "VmfUtil.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(GeneticAlgorithmInputGenerator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* GeneticAlgorithmInputGenerator::build(std::string name)
{
    return new GeneticAlgorithmInputGenerator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void GeneticAlgorithmInputGenerator::init(ConfigInterface& config)
{
    mutateCrashingCases = config.getBoolParam(getModuleName(), "enableMutationOfCrashes", false);

    mutators = MutatorModule::getMutatorSubmodules(config,getModuleName());

    int size = (int) mutators.size();
    if(0 == size)
    {
        throw RuntimeException("GeneticAlgorithmInputGenerator must be configured with at least one child mutator",
                                RuntimeException::CONFIGURATION_ERROR);
    }
    
}

/**
 * @brief Construct a new Genetic Algorithm Input Generator module
 * 
 * @param name the name of the module
 */
GeneticAlgorithmInputGenerator::GeneticAlgorithmInputGenerator(std::string name) :
    InputGeneratorModule(name)
{

}


GeneticAlgorithmInputGenerator::~GeneticAlgorithmInputGenerator()
{

}


void GeneticAlgorithmInputGenerator::registerStorageNeeds(StorageRegistry& registry)
{
   normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);
   mutatorIdKey = registry.registerIntKey("MUTATOR_ID", StorageRegistry::WRITE_ONLY, 1);
   testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_WRITE);
}

void GeneticAlgorithmInputGenerator::addNewTestCases(StorageModule& storage)
{
    StorageEntry* baseTestCase = selectBaseEntry(storage);

    if(nullptr != baseTestCase)
    {
        for(size_t i=0; i<mutators.size(); i++)
        {
            StorageEntry* newEntry = storage.createNewEntry();
            MutatorModule* mutator = mutators[i];
            mutator->mutateTestCase(storage, baseTestCase, newEntry, testCaseKey);
            newEntry->setValue(mutatorIdKey, mutator->getID());
        }
    }
}

/**
 * @brief Helper method to select the base entry to mutate
 * 
 * This implementation uses a weighted random selection that favors entries with lower indices
 * 
 * @param storage the storage module 
 * @return StorageEntry* the base entry to use
 */
StorageEntry* GeneticAlgorithmInputGenerator::selectBaseEntry(StorageModule& storage)
{
    StorageEntry* baseTestCase = nullptr;
    std::unique_ptr<Iterator> entries;
    if(mutateCrashingCases)
    {
        //Use all the entries in the corpus, even those that are CRASHED or HUNG
        entries = storage.getSavedEntries();
    }
    else
    {
        //Use only the entries in the corpus that ran normally
        entries = storage.getSavedEntriesByTag(normalTag);
    }

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
