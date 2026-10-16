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
 *
 * ===========================================================================*/
#include "AFLDiffFeedback.hpp"
#include "Iterator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "StorageEntry.hpp"
#include "StorageRegistry.hpp"
#include "VmfUtil.hpp"
#include "ExecutorModule.hpp"
#include "plog/Log.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <memory>
#include <numeric>
#include <utility>
#include <vector>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLDiffFeedback);



Module* AFLDiffFeedback::build(std::string name)
{
    return new AFLDiffFeedback(name);
}

void AFLDiffFeedback::init(ConfigInterface& config)
{
    outputDir = config.getOutputDir();
    useCustomWeights = config.getBoolParam(getModuleName(),"useCustomWeights", false);
    sizeFitnessWeight = config.getFloatParam(getModuleName(), "sizeWeight", 1.0);
    speedFitnessWeight = config.getFloatParam(getModuleName(), "speedWeight", 5.0);
    diffFitnessWeight = config.getFloatParam(getModuleName(), "diffWeight", diffFitnessWeight);
    expectedSUT = config.getStringParam(getModuleName(), "systemOfTruth");

    auto execs = ExecutorModule::getExecutorSubmodules(config, 
        config.getSuperModule(getModuleName())->getModuleName());
    unsigned long numExecutors = execs.size();
    
    for(auto const& e : execs)
    {
        auto n = e->getModuleName();
        execNameTags.emplace(std::make_pair(n, 0));
        if(n == expectedSUT)
            isExpectedReal = true;
    }

    if(!isExpectedReal)
    {
        if(numExecutors < 3)
        {
            throw RuntimeException("Differential Feedback between 2 SUTs must have a reference of correctness. YAML config: systemOfTruth",
                    RuntimeException::USAGE_ERROR);
        }
        else
        {
            LOG_WARNING << "Differential Feedback without a reference of correctness will default "
             << "to majority voting, and \"RAN_SUCCESSFULLY\" upon voting failure. Is this your intent?";
        }
    }
    


    // module name -> tagID -> pass result w/ tagId as src of truth    
    
    avgExecTimePerExec.resize(numExecutors, 0);
    maxExecTimePerExec.resize(numExecutors, 0);
    avgTestCaseSizePerExec.resize(numExecutors, 0);
    maxTestCaseSizePerExec.resize(numExecutors, 0);

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

AFLDiffFeedback::AFLDiffFeedback(std::string name) :
    FeedbackModule(name)
{
    avgExecTimePerExec = {};
    maxExecTimePerExec = {};
    avgTestCaseSizePerExec = {};
    maxTestCaseSizePerExec = {};
    numTestCases = 0;

    //These should all be set in config
    sizeFitnessWeight = 0;
    speedFitnessWeight = 0;
    diffFitnessWeight = 10;
    useCustomWeights = false;
    isExpectedReal = false;

    //These should all be set during registration
    testCaseKey = 0;
    coverageByteCountKey = 0;
    fitnessKey = 0;
    hasNewCoverageTag = 0;
    execTimeKey = 0;
    crashedTag = 0;
    hungTag = 0;
    expectedSUTTag = 0;

    deviantTag = 0;
}

AFLDiffFeedback::~AFLDiffFeedback()
{

}

void AFLDiffFeedback::registerStorageNeeds(StorageRegistry& registry)
{
    //Inputs
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    execTimeKey = registry.registerKey("EXEC_TIME_US", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    coverageByteCountKey = registry.registerKey("COVERAGE_COUNT", StorageRegistry::UINT, StorageRegistry::READ_ONLY);
    batchNumIdKey = registry.registerKey("ENTRY_BATCH_NUM", StorageRegistry::U64, StorageRegistry::READ_ONLY);
    hasNewCoverageTag = registry.registerTag("HAS_NEW_COVERAGE", StorageRegistry::READ_ONLY);

    crashedTag = registry.registerTag("CRASHED", StorageRegistry::READ_ONLY);
    hungTag = registry.registerTag("HUNG", StorageRegistry::READ_ONLY);
    deviantTag = registry.registerTag("DEVIATED", StorageRegistry::WRITE_ONLY);

    for(auto const& pair : execNameTags)
    {
        execNameTags[pair.first] = registry.registerTag(pair.first, StorageRegistry::READ_ONLY);
    }
    expectedSUTTag = isExpectedReal ? execNameTags[expectedSUT] : expectedSUTTag;

    //Outputs
    fitnessKey = registry.registerKey("FITNESS", StorageRegistry::FLOAT, StorageRegistry::WRITE_ONLY);
}
  
void AFLDiffFeedback::evaluateTestCaseResults(StorageModule& storage, std::unique_ptr<Iterator>& entries)
{
    LOG_ERROR << "Differrential feedback REQUIRES more than one iterator of Storage Entries. Please use evaluate-DIFF-TestCaseResults";
    throw RuntimeException("Differential Feedback module does not support single-iterator feedback.", 
                            RuntimeException::USAGE_ERROR);
}

void AFLDiffFeedback::evaluateDiffTestCaseResults(StorageModule& storage, std::vector<std::unique_ptr<Iterator>>& entries)
{
    unsigned long numSUTs = entries.size();
    std::vector<StorageEntry*> entryBatch(numSUTs);
    // while( every Iterator still has entries )
    while( std::all_of(entries.begin(), entries.end(), [](std::unique_ptr<Iterator>& x){ return x->hasNext(); }))
    {
        std::transform(entries.begin(), entries.end(), entryBatch.begin(), [](std::unique_ptr<Iterator>& x){ 
            return x->getNext();
        });

        if( !assertSharedBatch(entryBatch) )
        {
            LOG_ERROR << "An unexpected usage exception was thrown, but not properly handled. Aborting feedback...";
            break;
        }
        
        std::vector<unsigned int> execTimes(numSUTs, 0);
        std::transform(entryBatch.begin(), entryBatch.end(), execTimes.begin(), [this](StorageEntry* e){
            return getExecTimeMs(e);
        });
        for(size_t i=0; i < maxExecTimePerExec.size(); i++)
        {
            if(execTimes[i] > maxExecTimePerExec[i])
            {
                maxExecTimePerExec[i] = execTimes[i];
            }
        }
        for(size_t i=0; i < avgExecTimePerExec.size(); i++)
        {
            avgExecTimePerExec[i] = ((avgExecTimePerExec[i] * numTestCases/numSUTs) + execTimes[i])
                / (static_cast<float>(numTestCases)/numSUTs + 1);
        }

        int& tcKeyRef = testCaseKey;
        std::vector<int> entrySizes(numSUTs, 0);
        std::transform(entryBatch.begin(), entryBatch.end(), entrySizes.begin(), [tcKeyRef](StorageEntry* e){
            return e->getBufferSize(tcKeyRef);
        });
        for(size_t i=0; i < maxTestCaseSizePerExec.size(); i++)
        {
            if(entrySizes[i] > maxTestCaseSizePerExec[i])
            {
                maxTestCaseSizePerExec[i] = entrySizes[i];
            }
        }
        for(size_t i=0; i < avgTestCaseSizePerExec.size(); i++)
        {
            avgTestCaseSizePerExec[i] = ((avgTestCaseSizePerExec[i] * numTestCases/numSUTs) + entrySizes[i]) / (static_cast<float>(numTestCases)/numSUTs + 1);
        }

        numTestCases += numSUTs;

        // Calculate fitness if any of the testcases have new coverage OR their end state differed
        int& newCovgRef = hasNewCoverageTag;
        end_state expected = safe;
        for(auto const& e : entryBatch)
        {
            if(e->hasTag(expectedSUTTag))
            {
                expected = getEndState(e);
            }
        }
        
        bool anyHasCovg = std::any_of(entryBatch.begin(), entryBatch.end(),[newCovgRef](StorageEntry* e){ return e->hasTag(newCovgRef); });
        auto const& devs = findEndStateDeviants(entryBatch, expected, anyHasCovg);
        if( anyHasCovg || devs.size() > 0)
        {
            std::vector<unsigned int> coverage(numSUTs, 0);
            int& covgBCRef = coverageByteCountKey;
            std::transform(entryBatch.begin(), entryBatch.end(), coverage.begin(), [covgBCRef](StorageEntry* e){
                return e->getUIntValue(covgBCRef);
            }); 

            std::vector<float> execFitnesses = computeDiffFitness(entryBatch, coverage, execTimes, entrySizes, devs);

            for(size_t i=0; i < entryBatch.size(); i++)
            {
                if(execFitnesses[i] > 0)
                {
                    entryBatch[i]->setValue(fitnessKey, execFitnesses[i]);
                    storage.saveEntry(entryBatch[i]);
                }
            }
        }
    }
}

std::vector<float> AFLDiffFeedback::computeDiffFitness(std::vector<StorageEntry*>& entries, 
    std::vector<unsigned int>& covg, std::vector<unsigned int>& execT, std::vector<int>& sizes,
    std::vector<unsigned long> deviants)
{
    std::vector<float> fits(covg.size(), 1.0);
    if(useCustomWeights)
    {
        std::transform(covg.begin(), covg.end(), fits.begin(), [](unsigned int c){ return (float)log10(c) + 1; });
        float normalizedSpeed; float normalizedSize;
        for(size_t j=0; j<covg.size(); j++)
        {
            normalizedSpeed = (float)1.0 - execT[j] / maxExecTimePerExec[j];
            normalizedSize = (float)1.0 - sizes[j] / maxTestCaseSizePerExec[j];
            fits[j] *= (float) ((1.0 + normalizedSpeed * speedFitnessWeight) * (1.0 + normalizedSize * sizeFitnessWeight));
        }
    }
    else
    {
        for(size_t j=0; j<covg.size(); j++)
        {
            // Greatly favor AFL coverage and somewhat consider execTime and entrySize
            fits[j] *= (float)log10(covg[j]) + 1;
            fits[j] *= (avgExecTimePerExec[j] / execT[j]);
            fits[j] *= (avgTestCaseSizePerExec[j] / sizes[j]);
        }
    }
    
    

    // HIGHLY prioritize entries that differ from our voted on / expected result
    for(auto const& x : deviants)
    {
        fits[x] *= diffFitnessWeight;
    }
    
    // remove negative fitness
    std::transform(fits.begin(), fits.end(), fits.begin(), [](float f){ return f<0 ? 0 : f; });
    
    return fits;
}

unsigned int AFLDiffFeedback::getExecTimeMs(StorageEntry* e)
{
    unsigned int execTimeUs = e->getUIntValue(execTimeKey);
    unsigned int execTimeMs = 1;
    if(execTimeUs > 1000) //This is needed to prevent an execution time of 0ms
    {
        execTimeMs = execTimeUs / 1000;
    }
    return execTimeMs;
}

std::vector<unsigned long> AFLDiffFeedback::findEndStateDeviants(std::vector<StorageEntry*>& batch, AFLDiffFeedback::end_state def, bool hasNewCovg)
{
    std::vector<unsigned long> ret = {};
    end_state decision = def;

    if(batch.size() > 2)
    {
        // Boyer-moore majority voting
        int votes = 0;
        for(size_t i=0; i<batch.size(); i++)
        {
            if(votes == 0)
            {
                decision = getEndState(batch[i]);
                votes = 1;
            }
            else 
            {
                if(getEndState(batch[i]) == decision)
                    votes++;
                else 
                    votes--;
            }
        }
    }
    // put any that did NOT MATCH into the ret map
    for(unsigned long i=0; i<batch.size(); i++)
    {
        if(getEndState(batch[i]) != decision)
        {
            ret.emplace_back(i);
        }
    }
    
    if(batch.size() > 2 && ret.size() > batch.size()/2)
    {
        LOG_WARNING << "Differential Feedback could not determine majority execution result by voting - defaulting to trusted end_state";
        
        decision = def;
        for(unsigned long i=0; i<batch.size(); i++)
        {
            if(getEndState(batch[i]) != decision)
                ret.emplace_back(i);
        }
    }

    if(decision != def)
    {
        LOG_INFO << "Differential Feedback voted and agreed on " << end_state_str[decision] << " instead of " << end_state_str[def]; 
    }

    if(ret.size() > 0)
    {
        LOG_DEBUG << "Following SUTs did not match the expected state, " << end_state_str[decision] << ":";
        for(unsigned long& i : ret)
        {
            batch[i]->addTag(deviantTag);
            LOG_DEBUG << '\t' << getExecName(batch[i]) << ": " << end_state_str[getEndState(batch[i])];
        }
        
        
        // write out file iff one of the states had new coverage
        if(hasNewCovg)
        {
            char* buffer = batch[0]->getBufferPointer(testCaseKey);
            int size = batch[0]->getBufferSize(testCaseKey);
            std::string filename = std::to_string(batch[0]->getID());
            std::string deviant_dir = outputDir+"/testcases/deviants/";
            for(auto const& e : batch)
            {
                deviant_dir = deviant_dir+getExecName(e)+"_"+end_state_str[getEndState(e)]+"/";
            }

            // create a file name with id
            LOG_DEBUG << "\tthe input buffer, ID " << filename << " will be written to disk.";
            VmfUtil::createDirectory(deviant_dir.c_str());
            VmfUtil::writeBufferToFile(deviant_dir, filename, buffer, size);
        }
    }

    return ret;
}

AFLDiffFeedback::end_state AFLDiffFeedback::getEndState(StorageEntry* e)
{
    if(e->hasTag(crashedTag))
        return crash;
    else if(e->hasTag(hungTag))
        return hang;
    else
        return safe;
}

std::string AFLDiffFeedback::getExecName(StorageEntry* e)
{
    for(auto const& pair : execNameTags)
    {
        if(e->hasTag(pair.second))
            return pair.first;
    }
    throw RuntimeException("Uh oh. How did this entry make it through without a Executor Name Tag?",
            RuntimeException::UNEXPECTED_ERROR);
    return "";
}

bool AFLDiffFeedback::assertSharedBatch(std::vector<StorageEntry*>& batch)
{
    unsigned long long batch_num = batch[0]->getU64Value(batchNumIdKey);
    int cpy = batchNumIdKey;
    if(std::all_of(batch.begin(), batch.end(), [&batch_num, &cpy](StorageEntry* e){ return (e->getU64Value(cpy) == batch_num); }))
    {
        return true;
    }
    else
    {
        std::cout << "Entry IDs: ";
        for(auto const& e : batch){ std::cout << e->getID() << " "; }
        std::cout << "\n";
        throw RuntimeException("[ FATAL ] Feedback pulled a batch from the StorageIterator whose IDs did not all match.",
                RuntimeException::UNEXPECTED_ERROR);
    }
}
