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
#include "AnalysisController.hpp"
#include "Logging.hpp"
#include "CDMSCommandAndCorpusHandler.hpp"

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AnalysisController);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AnalysisController::build(std::string name)
{
    return new AnalysisController(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void AnalysisController::init(ConfigInterface& config)
{
    ControllerModulePattern::init(config);

    //Read in the output modules ourself, because we don't want to use the OutputScheduler for this controller
    outputs = OutputModule::getOutputSubmodules(config, getModuleName());

    //At least one executor and feedback module are required
    if((0 == executors.size()) || (0 == feedbacks.size()))
    {
            throw RuntimeException("This controller requrires at least one Executor and FeedbackModule",
                                   RuntimeException::CONFIGURATION_ERROR);
    }

}

/**
 * @brief Construct a new Iterative Controller object
 * 
 * @param name the name o the module
 */
AnalysisController::AnalysisController(
    std::string name) :
    ControllerModulePattern(name)
{

}

AnalysisController::~AnalysisController()
{

}


bool AnalysisController::run(StorageModule& storage, bool firstPass)
{
    if(firstPass)
    {
        //Run any initialization modules
        for(InitializationModule* m: initializations)
        {
            m->run(storage);
        }

        //Calibrate the executors
        calibrate(storage);

        //Run any input generator modules
        for(InputGeneratorModule* m: inputGenerators)
        {
            m->addNewTestCases(storage);
        }
    }

    //Execute the test cases
    executeTestCases(firstPass, storage);
    
    //Let the input generators evaluate any results
    for(InputGeneratorModule* m: inputGenerators)
    {
        //Ignore the results, as we don't care if the input generators are done, since they only run once anyway
        m->examineTestCaseResults(storage);
    }

    //Now clear the new list.
    //This will also delete any discarded new entries
    storage.clearNewAndLocalEntries();

    //In standalone mode, moreTestCasesToLoad will always be false
    bool moreTestCasesToLoad = CDMSCommandAndCorpusHandler::getInstance().hasMoreFilesToLoad();

    //Run the output modules only at the end, after all test cases have been executed
    if(!moreTestCasesToLoad)
    {
        //Run any output modules
        for(OutputModule* m: outputs)
        {
            m->run(storage);
        }
    }

    //Execution is complete as long as all of the test cases have been loaded
    //This is always the case in standalone mode, but in distruted mode there could be
    //lingering test cases
    return !moreTestCasesToLoad;
}



