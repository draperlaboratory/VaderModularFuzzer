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
#include "TemplateFeedback.hpp"
#include "Logging.hpp"
#include "VmfRand.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(TemplateFeedback);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* TemplateFeedback::build(std::string name)
{
    return new TemplateFeedback(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void TemplateFeedback::init(ConfigInterface& config)
{
    //Call upon the config option to read any config parameters, such as
    //config.getIntParam(getModuleName(), "parameterName");
}

/**
 * @brief Construct a new TemplateFeedback::TemplateFeedback object
 * 
 * @param name name of instance 
 */
TemplateFeedback::TemplateFeedback(std::string name) :
    FeedbackModule(name)
{
}

/**
 * @brief Destroy the TemplateFeedback::TemplateFeedback object
 */
TemplateFeedback::~TemplateFeedback()
{
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void TemplateFeedback::registerStorageNeeds(StorageRegistry& registry)
{
    fitnessKey = registry.registerKey("FITNESS", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
}

/**
 * @brief Evaluate the test case results
 * This method must:
 * 1) compute and save the sort by key (e.g fitness) to the storage entry
 * 2) save any other values of interest to the storage entry, including tagging the entry if relevant
 * 3) determine if the test case is interesting enough to save in long term storage (and save the entry if it is)
 * 
 * @param storage 
 * @param entries 
 */
void TemplateFeedback::evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries)
{
    while(entries->hasNext())
    {
        StorageEntry* entry = entries->getNext();

        //Real feedback modules will have more robust algorithms for deciding if a test case is interesting
        //and for computing the fitness.  Here we just keep every 10th test case and insert a random fitness
        //value
        if((entry->getID() % 10) == 0)
        {
            float fitness = (float)VmfRand::getInstance()->randBetween(0,100);
            entry->setValue(fitnessKey, fitness);
            storage.saveEntry(entry);
        }
    }

}

/* ------------The methods below are optional for FeedbackModules -------------- */

/**
 * @brief Modules using global metadata must also register fields that they intend to read or write
 *
 * Not all modules use metadata (which is summary data collected across the entries stored in storage),
 * hence this is an optional method.
 *
 * @param registry
 */
/*void TemplateFeedback::registerMetadataNeeds(StorageRegistry& registry)
{

}*/