/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2024 The Charles Stark Draper Laboratory, Inc.
 * <vmf@draper.com>
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
#include "AFLFeedback.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include <cmath>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLFeedback);


/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLFeedback::build(std::string name)
{
    return new AFLFeedback(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void AFLFeedback::init(ConfigInterface& config)
{
    outputDir = config.getOutputDir();
    useCustomWeights = config.getBoolParam(getModuleName(),"useCustomWeights", false);
    sizeFitnessWeight = config.getFloatParam(getModuleName(), "sizeWeight", 1.0);
    speedFitnessWeight = config.getFloatParam(getModuleName(), "speedWeight", 5.0);

    if(useCustomWeights) 
    {
        if(sizeFitnessWeight < 0.0 || speedFitnessWeight < 0.0) 
        {
            throw RuntimeException("One or more Custom Fitness Weights for feedback is invalid",
                    RuntimeException::USAGE_ERROR);
        }
        LOG_INFO << "Fitness weights: speed = " << speedFitnessWeight << ", size = " << sizeFitnessWeight;
    }
    else   
        LOG_INFO << "Using AFL++ style Fitness algorithm";
}

AFLFeedback::AFLFeedback(std::string name) :
    FeedbackModule(name)
{
    avgExecTime = 0;
    maxExecTime = 0;
    maxTestCaseSize = 0;
    numTestCases = 0;
}

AFLFeedback::~AFLFeedback()
{

}

void AFLFeedback::registerStorageNeeds(StorageRegistry& registry)
{
    //Inputs
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    execTimeKey = registry.registerKey("EXEC_TIME_US", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    coverageByteCountKey = registry.registerKey("COVERAGE_COUNT", StorageRegistry::INT, StorageRegistry::READ_ONLY);
   
    crashedTag = registry.registerTag("CRASHED", StorageRegistry::WRITE_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::WRITE_ONLY);
    normalTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::WRITE_ONLY);
    hasNewCoverageTag = registry.registerTag("HAS_NEW_COVERAGE", StorageRegistry::WRITE_ONLY);

    //Outputs
    fitnessKey = registry.registerKey("FITNESS", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
}
  
void AFLFeedback::registerMetadataNeeds(StorageRegistry& registry)
{
    crashedTotalMetadata = registry.registerKey("TOTAL_CRASHED_CASES", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
    hungTotalMetadata = registry.registerKey("TOTAL_HUNG_CASES", StorageRegistry::INT, StorageRegistry::WRITE_ONLY);
}


void AFLFeedback::evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries)
{
    StorageEntry& metadata = storage.getMetadata();

    while(entries->hasNext())
    {
        StorageEntry* e = entries->getNext();

        //Compute average metrics
        int execTime = getExecTimeMs(e);
        avgExecTime = ((avgExecTime * numTestCases) + execTime)/(numTestCases + 1);
        if (execTime > maxExecTime)
            maxExecTime = execTime;

        int size = e->getBufferSize(testCaseKey);
        avgTestCaseSize = ((avgTestCaseSize * numTestCases) + size)/(numTestCases + 1);
        if (size > maxTestCaseSize)
            maxTestCaseSize = size;

        numTestCases++;

        //Update metadata for anything crashed or hung
        if(e->hasTag(crashedTag))
        {
            metadata.incrementIntValue(crashedTotalMetadata);
        }
        else if(e->hasTag(hungTag))
        {
            metadata.incrementIntValue(hungTotalMetadata);
        }

        //Then check to see if any new paths were uncovered by this test case
        if(e->hasTag(hasNewCoverageTag))
        {
            //Compute the fitness
            float fitness = computeFitness(storage, e);
            if(fitness > 0)
            {
                e->setValue(fitnessKey, fitness);

                //Then save the entry
                storage.saveEntry(e);
            }
            //Toss the test case if it has negative fitness
            //(This should not happen, but has been observed due to unknown causes)
        }
    }
}

float AFLFeedback::computeFitness(StorageModule& storage, StorageEntry* e)
{
    int coverage = e->getIntValue(coverageByteCountKey); 
    int execTime = getExecTimeMs(e);
    int size = e->getBufferSize(testCaseKey);

    float fitness = 0;
    if(useCustomWeights)
    {
        fitness = log10(coverage) + 1;

        // Compute normalized speed and size; use 1 minus the value because they are inversely related to fitness
        float normalizedSpeed = 1.0 - execTime / maxExecTime;
        float normalizedSize = 1.0 - size / maxTestCaseSize;

        // Apply size and speed weights to fitness
        fitness *= (1.0 + normalizedSpeed * speedFitnessWeight) * (1.0 + normalizedSize * sizeFitnessWeight);
    }
    else
    {
        //Use an algorithm that is closer to what AFL++ uses
        fitness = 1.0; 
        // Prioritize testcases with high coverage 
        fitness *= log10(coverage) + 1; 
        // Adjust weight based on execution speed of this testcase compared to average 
        fitness *= (avgExecTime / execTime) ;
        // Adjust weight based on size of this testcase compared to average
        fitness *= (avgTestCaseSize / size); 

    }

    if (fitness < 0.0)
    {
        //TODO(VADER-1298): Negative fitness values should not happen, but have been observed
        //This code will at least prevent the fuzzer from shutting down if this occurs,
        //as well as log the underlying test case to disk for further analysis.
        LOG_ERROR << "Negative fitness value (this should not be possible) " << fitness;  
        LOG_ERROR << "Inputs were: coverage=" << coverage << ", execTime=" << execTime << " (avg " << 
                  avgExecTime << "), size=" << size << " (avg " << avgTestCaseSize << ")";
        char* buffer = e->getBufferPointer(testCaseKey);
        unsigned long id = e->getID();

        // create a file name with id
        std::string filename = std::to_string(id) + "_NegativeFitnessValue";
        VmfUtil::writeBufferToFile(outputDir, filename, buffer, size);
        LOG_ERROR << "Test case logged to output directory with filename " << filename;
        LOG_ERROR << "This test case will be discarded.";
    }

    return fitness;
}

int AFLFeedback::getExecTimeMs(StorageEntry* e)
{
    int execTimeUs = e->getIntValue(execTimeKey);
    int execTimeMs = 1;
    if(execTimeUs > 1000) //This is needed to prevent an execution time of 0ms
    {
        execTimeMs = execTimeUs / 1000;
    }
    return execTimeMs;
}
