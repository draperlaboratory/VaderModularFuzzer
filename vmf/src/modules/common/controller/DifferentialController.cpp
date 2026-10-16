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
#include "DifferentialController.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "plog/Log.h"
#include <algorithm>
#include <list>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(DifferentialController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* DifferentialController::build(std::string name)
{
    return new DifferentialController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void DifferentialController::init(ConfigInterface& config)
{
    ControllerModulePattern::init(config);
    
    if(1 >= executors.size())
    {
        throw RuntimeException("DifferentialController requires at least two ExecutorModules",
                                RuntimeException::USAGE_ERROR);
    }

    if(1 != feedbacks.size())
    {
        throw RuntimeException("DifferentialController requires a single FeedbackModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }

    if(1 != inputGenerators.size())
    {
        throw RuntimeException("DifferentialController requires a single InputGeneratorModule",
                                RuntimeException::CONFIGURATION_ERROR);
    }
    executorIdTags = {};
    batchNumIdKey = 0;

    //Initialization and output modules are optional, and any number are supported
}

/**
 * @brief Register differential controller to read the executor tags
 * 
 * @param registry
 */
void DifferentialController::registerStorageNeeds(StorageRegistry& registry)
{
    for(auto const& e : executors)
    {
        executorIdTags.emplace_back(
            registry.registerTag(e->getModuleName(), StorageRegistry::READ_ONLY)
        );
    }
    batchNumIdKey = registry.registerU64Key("ENTRY_BATCH_NUM", StorageRegistry::READ_ONLY,0);
}

/**
 * @brief Construct a new Differential Controller object
 * 
 * @param name the name o the module
 */
DifferentialController::DifferentialController(
    std::string name) :
    ControllerModulePattern(name)
{

}

DifferentialController::~DifferentialController()
{

}


bool DifferentialController::run(StorageModule& storage, bool firstPass)
{
    bool done = false;
    if(firstPass)
    {
        performInitialSetupAndCalibration(storage);
    }

    executeTestCases(firstPass, storage);

    analyzeResults(firstPass, storage);

    done = generateNewTestCases(firstPass, storage); //also clears the new list
    if(done)
    {
        LOG_INFO << "Fuzzing complete -- our own input generator indicated completion";
    }

    done = hasExecutionTimeCompleted();

    return done;
}

/**
 * @brief Execute test cases meant only for each specific executor
 * 
 * Overwritten from ControllerModulePattern.
 * 
 * @param firstPass true if this is the first pass through the fuzzing loop
 * @param storage the storage module
 */
void DifferentialController::executeTestCases(bool firstPass, StorageModule& storage)
{
    std::unique_ptr<Iterator> storageIterator;

    for(size_t i=0; i<executors.size(); i++)
    {
        storageIterator = firstPass ? storage.getNewEntries() : storage.getNewEntriesByTag(executorIdTags[i]);
        executors[i]->runTestCases(storage, storageIterator);
    }

    int& batchRef = batchNumIdKey;

    // Request new entries f/e executor, sorted by batch number
    std::vector<std::unique_ptr<Iterator>> newEntriesByExecutor;
    for(int id : executorIdTags)
    {
        newEntriesByExecutor.emplace_back(
            storage.getKeySortedNewEntriesByTag(id, [batchRef](StorageEntry* e, StorageEntry* f){
                return e->getU64Value(batchRef) < f->getU64Value(batchRef);
            })
        );
    }

    if(std::any_of(newEntriesByExecutor.begin(), newEntriesByExecutor.end(), [](auto const& i){ return i == nullptr ;}))
    {
        return;
    }

    for(FeedbackModule* feedback: feedbacks)
    {
        feedback->evaluateDiffTestCaseResults(storage, newEntriesByExecutor);
        storageIterator->resetIndex();
    }    
}