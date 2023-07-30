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
#include "GeneticAlgorithmInputGenerator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "VaderUtil.hpp"

using namespace vader;

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

    int size = mutators.size();
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
}

void GeneticAlgorithmInputGenerator::addNewTestCases(StorageModule& storage)
{
    StorageEntry* baseTestCase = selectBaseEntry(storage);

    if(nullptr != baseTestCase)
    {
        for(size_t i=0; i<mutators.size(); i++)
        {
            mutators[i]->createTestCase(storage, baseTestCase);
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
        entries = storage.getEntries();
    }
    else
    {
        //Use only the entries in the corpus that ran normally
        entries = storage.getEntriesByTag(normalTag);
    }

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
