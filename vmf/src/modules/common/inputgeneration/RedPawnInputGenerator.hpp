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
#pragma once
#include <random> // colorize needs real randomness
#include <unordered_set> // for testcase pruning
#include <tuple>
#include "ExecutorModule.hpp"
#include "InputGeneratorModule.hpp"
#include "MutatorModule.hpp"
#include "RedPawnTransforms.hpp"

namespace vmf
{

// Enum to track the batching (pause/resume) state of RedPawn.
enum RedPawnMode {StartNewTestCase, FinishTestCase, MoreTestCasesInQueue};

/**
 * @brief Input generator that performs an input-to-state analysis comparable to RedQueen or AFL CmpLog.
 */
class RedPawnInputGenerator: public InputGeneratorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void addNewTestCases(StorageModule& storage);
    virtual bool examineTestCaseResults(StorageModule& storage);

    RedPawnInputGenerator(std::string name);
    virtual ~RedPawnInputGenerator();

private:
    bool colorize(StorageModule& storage, StorageEntry * baseEntry, int size, char * colorized_testcase);
    void getUniformlyRandomBytes(char* outbuff, int size);

    void collectLogEntries(StorageModule& storage, StorageEntry * baseEntry, char * colorized_testcase);
    bool generateRedPawnCandidates(StorageModule& storage);
    std::vector<uint>* findMatchesOfPattern(char * testcase, char * colorized_testcase, int length, uint64_t base_pattern, uint64_t colorized_pattern, int compare_size);
    bool performPatternReplacements(char * testcase, int len, std::vector<uint>* indices, uint64_t replacement, int compare_size);
    bool performPatternReplacement(char * testcase, int size, int index, uint64_t replacement, int compare_size);

    bool addCandidateTestcase(char * buff, int size);
    void addCandidatesToStorage(StorageModule& storage);
    uint64_t hashTestCase(char * buffer, int size);
    void validateCmpLog(StorageModule& storage);
    bool canAddMoreTestCases();
    void printStats();

    RedPawnMode currentMode;
    
    // Keys and tags
    int newCoverageTag;
    int ranNormallyTag;
    int redPawnNewCoverageTag;
    int testCaseKey;
    int traceBitsKey;
    int cmpLogMapKey;
    int execTimeKey;

    // User-configurable parameters
    int colorizeMaxExecs = 1000;
    int batchSize = 5000;
    bool skipStaticLogEntries;

    // Stats tracking
    uint64_t testCasesGenerated, testCasesGeneratedTotal;
    uint64_t testCasesAdded, testCasesAddedTotal;
    uint64_t testCasesAddedByLastSeed;
    uint64_t testCasesInQueue;
    time_t timeStartedTestCase;
    uint64_t currTestCaseID;

    bool hasValidated = false;

    ExecutorModule* cmplog_executor;
    ExecutorModule* regular_executor;

    std::mt19937_64 rng;
    std::uniform_int_distribution<u_int32_t> uni_uint;

    char * base_testcase, * colorized_testcase;
    int size;
    uint64_t currentLogIndex = 0;

    std::unordered_set<uint64_t> addedHashes;
    std::vector<std::pair<char*, int>> candidates;
    std::vector<std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, int, int>> logEntries;
    std::vector<std::pair<int, int>> taintRegions;

    std::vector<RedPawnEncodingTransform*> encodingTransforms;
    std::vector<RedPawnArithmeticTransform*> arithmeticTransforms;
};
}
