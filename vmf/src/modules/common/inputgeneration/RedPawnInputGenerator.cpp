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
#include "RedPawnInputGenerator.hpp"
#include "RedPawnCmpLogMap.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "VmfUtil.hpp"
#include <queue> // for colorize heap

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(RedPawnInputGenerator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* RedPawnInputGenerator::build(std::string name)
{
    return new RedPawnInputGenerator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void RedPawnInputGenerator::init(ConfigInterface& config)
{

    cmplog_executor = nullptr;
    regular_executor = nullptr;

    std::vector<ExecutorModule*> executorList = ExecutorModule::getExecutorSubmodules(config, getModuleName());

    // Make sure we have at least two executors
    if (executorList.size() < 2)
    {
        throw RuntimeException("RedPawnInputGenerator requires at least two executors: one default and one cmplog.", RuntimeException::CONFIGURATION_ERROR);
    }

    // Locate the cmplog executor and raise an exception if we can't find one
    cmplog_executor = ExecutorModule::getExecutorSubmoduleByName(config, getModuleName(), "cmplogExecutor");
    if (cmplog_executor == nullptr)
    {
        throw RuntimeException("RedPawnInputGenerator did not find an executor named cmplogExecutor.", RuntimeException::CONFIGURATION_ERROR);
    }

    // Locate the regular executor for colorization and raise an exception if we can't find one
    regular_executor = ExecutorModule::getExecutorSubmoduleByName(config, getModuleName(), "colorizationExecutor");
    if (regular_executor == nullptr)
    {
        throw RuntimeException("RedPawnInputGenerator did not find an executor named colorizationExecutor.", RuntimeException::CONFIGURATION_ERROR);
    }

    // Load config options
    colorizeMaxExecs = config.getIntParam(getModuleName(), "colorizeMaxExecs", 1000);
    LOG_INFO << "RedPawn colorize bound set to " << colorizeMaxExecs << " executions.";

    batchSize = config.getIntParam(getModuleName(), "batchSize", 1000);
    LOG_INFO << "RedPawn set batch size to " << batchSize;

    // This is an optimization from the Improving CmpLog paper section 5.1.1. Default is on.
    skipStaticLogEntries = config.getBoolParam(getModuleName(), "skipStaticLogEntries", true);
    LOG_INFO << "skipStaticLogEntries optimization set to: " << skipStaticLogEntries;

    rng = std::mt19937_64(time(0));
    uni_uint = std::uniform_int_distribution<u_int32_t>(0, UINT32_MAX);

    // Determine which transforms to use. Default is all enabled.
    bool useDirectTransform = config.getBoolParam(getModuleName(), "useDirectTransform", true);
    bool useReverseBytesTransform = config.getBoolParam(getModuleName(), "useReverseBytesTransform", true);
    bool useOffsetTransform = config.getBoolParam(getModuleName(), "useOffsetTransform", true);
    bool useFactorTransform = config.getBoolParam(getModuleName(), "useFactorTransform", true);
    bool useXORTransform = config.getBoolParam(getModuleName(), "useXORTransform", true);

    // Add the requested transforms:
    // Encoding transforms
    if (useDirectTransform)
        encodingTransforms.push_back(new DirectTransform());
    if (useReverseBytesTransform)
        encodingTransforms.push_back(new ReverseBytesTransform());

    // Arithmetic transforms
    if (useOffsetTransform)
        arithmeticTransforms.push_back(new OffsetTransform());
    if (useFactorTransform)
        arithmeticTransforms.push_back(new FactorTransform());
    if (useXORTransform)
        arithmeticTransforms.push_back(new XORTransform());

    // Require at least 1 transform
    int transformsUsed = arithmeticTransforms.size() + encodingTransforms.size();
    if (transformsUsed < 1)
    {
        throw RuntimeException("RedPawnInputGenerator was configured with no transforms. Enable at least 1 transform.", RuntimeException::CONFIGURATION_ERROR);
    }
    LOG_INFO << "RedPawn configured with " << transformsUsed << " total transforms.";

    // Reset stats
    testCasesGenerated = 0;
    testCasesGeneratedTotal = 0;
    testCasesAdded = 0;
    testCasesAddedTotal = 0;
    testCasesAddedByLastSeed = 0;
    timeStartedTestCase = 0;
    currTestCaseID = 0;

    // Initialize mode to starting from a fresh testcase
    currentMode = StartNewTestCase;
}

/**
 * @brief Construct a new Genetic Algorithm Input Generator module
 * 
 * @param name the name of the module
 */
RedPawnInputGenerator::RedPawnInputGenerator(std::string name) :
    InputGeneratorModule(name)
{

}


RedPawnInputGenerator::~RedPawnInputGenerator()
{
    // Free transforms
    for (RedPawnArithmeticTransform * t : arithmeticTransforms)
        delete t;
    for (RedPawnEncodingTransform * t : encodingTransforms)
        delete t;

    // Free scratch space testcases
    if (colorized_testcase != NULL)
        free(colorized_testcase);
    if (base_testcase != NULL)
        free(base_testcase);
}


void RedPawnInputGenerator::registerStorageNeeds(StorageRegistry& registry)
{
    // Read
    newCoverageTag = registry.registerTag("HAS_NEW_COVERAGE", StorageRegistry::READ_ONLY);
    ranNormallyTag = registry.registerTag("RAN_SUCCESSFULLY", StorageRegistry::READ_ONLY);    
    testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    traceBitsKey = registry.registerKey("AFL_TRACE_BITS", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);
    execTimeKey = registry.registerKey("EXEC_TIME_US", StorageRegistry::INT, StorageRegistry::READ_ONLY);
    cmpLogMapKey = registry.registerKey("CMPLOG_MAP_BITS", StorageRegistry::BUFFER, StorageRegistry::READ_ONLY);

    // Write
    redPawnNewCoverageTag = registry.registerTag("REDPAWN_NEW_COVERAGE", StorageRegistry::READ_WRITE);
}


void RedPawnInputGenerator::addNewTestCases(StorageModule& storage)
{

    // On the first run ever, make sure we get cmplog data back from SUT or exit.
    if (!hasValidated)
    {
        validateCmpLog(storage);
        hasValidated = true;
    }

    std::unique_ptr<Iterator> storageIterator;

    //storageIterator = storage.getNewEntriesByTag(newCoverageTag);
    storageIterator = storage.getSavedEntriesByTag(redPawnNewCoverageTag);
    testCasesInQueue = storageIterator->getSize();

    printStats();

    // -------- First, finish off any work that needs resuming --------

    // When resuming, we skip colorization and collecting logs, because we already have them.
    if (currentMode == FinishTestCase)
    {
        bool finished = generateRedPawnCandidates(storage);
        addCandidatesToStorage(storage);

        // If we didn't finish, just return and leave mode as-is
        if (!finished)
        {
            return;
        } else {
            // If we are done, then clean up memory and state
            free(base_testcase);
            free(colorized_testcase);
            base_testcase = NULL;
            colorized_testcase = NULL;
            currentMode = StartNewTestCase;
        }
    }

    // ------- Start on a fresh testcase if we have at least one ---------

    if (testCasesInQueue > 0)
    {
        // Reset the stats for this testcase
        testCasesAddedByLastSeed = testCasesAdded;
        testCasesGenerated = 0;
        testCasesAdded = 0;
        addedHashes.clear();
        logEntries.clear();
        timeStartedTestCase = time(0);

        // Untag this entry now that it has been processed by RedPawn
        StorageEntry * entry = storageIterator -> getNext();
        entry -> removeTag(redPawnNewCoverageTag);

        // Make a copy of the testcase data
        size = entry -> getBufferSize(testCaseKey);
        base_testcase = (char *) malloc(size);
        memcpy(base_testcase, entry -> getBufferPointer(testCaseKey), size);
currTestCaseID = entry -> getID();

        // Create colorized version by first starting with a copy of the base testcase
        colorized_testcase = (char *) malloc(size);
        memcpy(colorized_testcase, base_testcase, size);

        // Then run the colorization algorithm to add as much entropy as possible
        bool colorize_success = colorize(storage, entry, size, colorized_testcase);

        // If colorization succeeds, run analysis
        bool done = true;
        if (colorize_success)
        {
            // Run both the initial and colorized entry, collect all the unique cmplog entries
            collectLogEntries(storage, entry, colorized_testcase);

            // Using the logs and all the enabled transforms, generate candidate testcases
            currentLogIndex = 0;
            done = generateRedPawnCandidates(storage);
        
            addCandidatesToStorage(storage);
        } else
        {
            LOG_DEBUG << "Colorization failed, not running RedPawn.";
        }

        // Depending on whether we were able to finish, either move on to next testcase
        // or just deposit a batch of results and resume next time we run.
        if (done)
        {
            free(colorized_testcase);
            free(base_testcase);
            colorized_testcase = NULL;
            base_testcase = NULL;
        } else {
            currentMode = FinishTestCase;
            return;
        }
    }

    // If we reach here, we finished whatever work we were doing.
    // Set mode to either StartNewTestCase or MoreTestCasesInQueue based on size of queue.
    if (testCasesInQueue > 1)
        currentMode = MoreTestCasesInQueue;
    else
        currentMode = StartNewTestCase;
    return;
}

/* @brief RedPawn returns true if it was either in the middle of working on a testcase
 * or if there are more testcases to process total. This enables it to run repeatedly
 * when there is more work to do. It returns false when there is nothing more to do,
 * and we need to wait for more new-coverage testcases.
 */
bool RedPawnInputGenerator::examineTestCaseResults(StorageModule& storage)
{

    // Locate all of the testcases that are marked with having new coverage this cycle.
    // We tag them our own RedPawn tag to indicate we haven't processed these yet.

    std::unique_ptr<Iterator> storageIterator;
    storageIterator = storage.getNewEntriesByTag(newCoverageTag);
    while (storageIterator -> hasNext())
    {
        StorageEntry * entry = storageIterator -> getNext();
        entry -> addTag(redPawnNewCoverageTag);
    }

    if (currentMode == FinishTestCase || currentMode == MoreTestCasesInQueue)
    {
        return true;
    }
    return false;
}

/**
 * @brief Before running, validate that things appear to be setup properly, eg we are
 *        indeed getting cmplog data back from the cmplog executor. This allows us to
 *        give useful error messages to user as soon as possible.
 *
 * @note It could be nice for modules to have a pre and post init functions so that
 *       they could test that things are working after all modules have finished pre init.
 */
void RedPawnInputGenerator::validateCmpLog(StorageModule& storage)
{
    // Get the first testcase
    std::unique_ptr<Iterator> storageIterator = storage.getSavedEntries();
    StorageEntry * entry = storageIterator -> getNext();

    if (entry != nullptr)
    {
        // Make a copy of the testcase
        StorageEntry * newEntry = storage.createLocalEntry();
        newEntry -> allocateAndCopyBuffer(testCaseKey, entry);
        
        // Run it on the cmplog executor
        cmplog_executor->runTestCase(storage, newEntry);
        int cmpLogMapSize = newEntry -> getBufferSize(cmpLogMapKey);
        if (cmpLogMapSize != sizeof(struct cmp_map))
        {
            LOG_ERROR << "CmpLogMap on testcase had size " << cmpLogMapSize << " instead of " << sizeof(struct cmp_map);
            throw RuntimeException("RedPawn unable to retrieve CmpLogMap from SUT.",
                                   RuntimeException::UNEXPECTED_ERROR);
        }
        cmp_map* cmp_map = (struct cmp_map *) newEntry -> getBufferPointer(cmpLogMapKey);
        
        // Make sure we have some cmplog entries
        int totalHits = 0;
        for (uint i = 0; i < CMP_MAP_W; i++)
        {
            totalHits += cmp_map->headers[i].hits;
        }
        
        if (totalHits == 0)
        {
            throw RuntimeException("RedPawn received an empty CmpLog map after execution.\n"
                                   "This probably means one of two things:\n"
                                   "1) Your SUT is not properly compiled with cmplog instrumentation.\n"
                                   "2) You have not configured RedPawn to use the right cmplog binary.\n"
                                   , RuntimeException::UNEXPECTED_ERROR);
        }
        
        LOG_INFO << "RedPawn validation passed. CmpLog appears to be working, found " << totalHits << " log entries.";
    } else {
        throw RuntimeException("Couldn't validate cmplog, there were no testcases.",
                               RuntimeException::UNEXPECTED_ERROR);
    }
}

/**
 * @brief Given a testcase and the colorized version of that testcases, we run them both on the
 * cmplog executor to get both of their cmplogs. We use this data to populate the logEntries
 * data structure.
*/
void RedPawnInputGenerator::collectLogEntries(StorageModule& storage, StorageEntry * baseEntry, char * colorizedTestcase)
{

    // Create a copy of the entry so we can run it.
    StorageEntry * newEntry = storage.createLocalEntry();
    newEntry -> allocateAndCopyBuffer(testCaseKey, baseEntry);

    // First we get the cmp_map (comparison log) for both the regular and colorized version of the testcase.
    // This requires running both of them with the CmpLog executor
    struct cmp_map* cmp_map;
    struct cmp_map* colorized_cmp_map;

    // Cmp_map for regular testcase
    cmplog_executor->runTestCase(storage, newEntry);
    if (newEntry -> getBufferSize(cmpLogMapKey) != sizeof(struct cmp_map))
    {
        throw RuntimeException("RedPawn unable to retrieve CmpLogMap from SUT (1).",
                               RuntimeException::UNEXPECTED_ERROR);
    }
    cmp_map = (struct cmp_map *) newEntry -> getBufferPointer(cmpLogMapKey);

    // Cmp_map for colorized testcase
    // Make a colorized copy to run
    StorageEntry * colorizedEntry = storage.createLocalEntry();
    colorizedEntry -> allocateAndCopyBuffer(testCaseKey, size, colorizedTestcase);

    cmplog_executor->runTestCase(storage, colorizedEntry);
    if (colorizedEntry -> getBufferSize(cmpLogMapKey) != sizeof(struct cmp_map))
    {
        throw RuntimeException("RedPawn unable to retrieve CmpLogMap from SUT (2).",
                               RuntimeException::UNEXPECTED_ERROR);
    }
    colorized_cmp_map = (struct cmp_map *) colorizedEntry -> getBufferPointer(cmpLogMapKey);

    int skipped_compare_too_large = 0;

    // Now we iterate through the cmp_map and add the records into logEntries.
    for (uint i = 0; i < CMP_MAP_W; i++)
    {
        // Skip empty log entries
        uint hit_count = cmp_map->headers[i].hits;
        if (hit_count == 0)
        {
            continue;
        }
        
        // Check for case where maps disagree
        if (colorized_cmp_map->headers[i].hits == 0)
        {
            // This happens when the base testcase and colorized testcase did not have identical
            // log entries filled in. This happens occasionally just from trace collisions etc.
            // It is safe to ignore.
            //LOG_DEBUG << "Warning: hit case where colorized map did not have same log as original testcase";
            continue;
        }
        
        // Skip function logs for now to focus on compare instructions
        if (cmp_map->headers[i].type == CMP_TYPE_RTN)
        {
            continue;
        }
        
        // Each index has a circular buffer of size CMP_MAP_H, so that is max index
        uint num_hit_entries = std::min((int)hit_count, CMP_MAP_H);
        
        int compare_size = cmp_map->headers[i].shape + 1; // Shape starts at 0
        int compare_type = cmp_map->headers[i].attribute;

        if (compare_size > 8)
        {
            skipped_compare_too_large++;
            continue;
        }

        // for each entry in the log for comparision id #i, see if we can find an I2S spot
        for (uint j=0; j < num_hit_entries; j++)
        {
            
            // Not that we only use the first 8 bytes of operands for now. The _128 fields have 8 more bytes.
            uint64_t og_lhs = cmp_map->log[i][j].v0;
            uint64_t og_rhs = cmp_map->log[i][j].v1;
            
            uint64_t co_lhs = colorized_cmp_map->log[i][j].v0;
            uint64_t co_rhs = colorized_cmp_map->log[i][j].v1;
            
            //LOG_INFO << "og_lhs: " << og_lhs << ", co_lhs: " << co_lhs;
            //LOG_INFO << "og_rhs: " << og_rhs << ", co_rhs: " << co_rhs;
            
            // Record this log entry
            // Skipping static entries optimization, improving cmplog paper section 5.1.1 https://arxiv.org/pdf/2211.08357.pdf
            // TODO: Another possible optimization is only adding *unique* entries (VADER-1232)
            if (skipStaticLogEntries && (og_lhs == co_lhs && og_rhs == co_rhs))
                continue;

            logEntries.push_back(std::make_tuple(og_lhs, og_rhs, co_lhs, co_rhs, compare_size, compare_type));
        }
    }

    if (skipped_compare_too_large > 0)
    {
        LOG_WARNING << "Skipped " << skipped_compare_too_large << " log entries for compares greater than 8 bytes (not supported yet)";
    }
}

// Returns a bool indicating whether or not it is done
bool RedPawnInputGenerator::generateRedPawnCandidates(StorageModule& storage)
{

    //LOG_INFO << "generateRedPawnCandidates starting at: " << currentLogIndex;

    // Track whether there is still room in the candidates vector. When full, we can exit early.
    bool candidatesFull = false;

    // Run for every log entry
    while (currentLogIndex  < logEntries.size())
    {

        printStats();
        //LOG_INFO << "At log index " << currentLogIndex;
        
        // Extract fields from log entry
        const auto& [og_lhs, og_rhs, co_lhs, co_rhs, compare_size, cmp_type] = logEntries[currentLogIndex];

        // We don't yet support compare sizes > 64 bits, and we can't perform analysis if testcase is smaller than compare size
        if (compare_size > 8 || compare_size > size)
        {
            continue;
        }

        //LOG_INFO << "Compare (" << og_lhs << " " << og_rhs << ") (" << co_lhs << " " << co_rhs << ") size: " << compare_size;
        
        // --------- Data Transforms -----------

        // Search testcase for this log entry pushed through all of our transform types
        for (RedPawnEncodingTransform * t : encodingTransforms)
        {
            // LOG_INFO << "Using transform " << t -> GetName();
            uint64_t og_lhs_decoded = t -> Decode(og_lhs, compare_size);
            uint64_t og_rhs_decoded = t -> Decode(og_rhs, compare_size);
            uint64_t co_lhs_decoded = t -> Decode(co_lhs, compare_size);
            uint64_t co_rhs_decoded = t -> Decode(co_rhs, compare_size);
            
            // Search for decoded value and replace instances with encoded value:
            
            // Left hand side
            std::vector<uint>* matches = findMatchesOfPattern(base_testcase, colorized_testcase, size, og_lhs_decoded, co_lhs_decoded, compare_size);
            bool res = performPatternReplacements(base_testcase, size, matches, t -> Encode(og_rhs, compare_size), compare_size);
            delete matches;
            if (!res)
            {
                candidatesFull = true;
                break;
            }

            // Right hand side
            matches = findMatchesOfPattern(base_testcase, colorized_testcase, size, og_rhs_decoded, co_rhs_decoded, compare_size);
            res = performPatternReplacements(base_testcase, size, matches, t -> Encode(og_lhs, compare_size), compare_size);
            delete matches;
            if (!res)
            {
                candidatesFull = true;
                break;
            }
        }

        // ---------- Arithmetic Transforms ----------------
        
        // Search over only the taint regions and find arithmetic transformations (eg offset +/- by an amount)
        
        for (const auto& [start, end] : taintRegions)
        {

            if (candidatesFull)
                break;

            int taintSize = end - start + 1;        
            // LOG_INFO << "Inspecting region of size " << taintSize << " from " << start << " to " << end;
            
            char * c = colorized_testcase + start;
            char * b = base_testcase + start;
            
            // Scan over taint region, looking at compare_size at a time
            for (int i = 0; i < taintSize; i++)
            {

                if (candidatesFull)
                    break;

                // Avoid going out of bounds, we can't do taintSize - compare_size
                // because we scan for more sizes.
                if (start + i + compare_size > size)
                    break;
                
                // Try every size in  2, 4, 8 that is less than or equal to compare size
                int this_size = 1;
                while (this_size < compare_size)
                {

                    if (candidatesFull)
                        break;

                    this_size *= 2;
                    
                    // LOG_INFO << "Trying size " << this_size;
                    
                    uint64_t colorizedVal = 0;
                    uint64_t baseVal = 0;
                    
                    switch (this_size)
                    {
                    case 1:
                        baseVal = *((uint8_t *)(b + i));
                        colorizedVal = *((uint8_t *)(c + i));
                        break;
                    case 2:
                        baseVal = *((uint16_t *)(b + i));
                        colorizedVal = *((uint16_t *)(c + i));
                        break;
                    case 3:
                    case 4:
                        baseVal = *((uint32_t *)(b + i));
                        colorizedVal = *((uint32_t *)(c + i));
                        break;
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                        baseVal = *((uint64_t *)(b + i));
                        colorizedVal = *((uint64_t *)(c + i));
                        break;
                    default:
                        break;
                    }

                    if (baseVal == colorizedVal)
                        continue;

                    // Try each arithmetic transform
                    for (RedPawnArithmeticTransform * t : arithmeticTransforms)
                    {
                        uint64_t result = 0;

                        // Attempt transform (left hand side)
                        if (t -> SolveTransform(baseVal, og_lhs, colorizedVal, co_lhs, result, co_rhs, this_size))
                        {
                            bool res = performPatternReplacement(base_testcase, size, start + i, result, this_size);
                            if (!res)
                            {
                                candidatesFull = true;
                                break;
                            }
                        }

                        // Attempt transform (right hand side)
                        if (t -> SolveTransform(baseVal, og_rhs, colorizedVal, co_rhs, result, co_lhs, this_size))
                        {
                            bool res = performPatternReplacement(base_testcase, size, start + i, result, this_size);
                            if (!res)
                            {
                                candidatesFull = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        currentLogIndex++;

        // If we have batchSize candidates, return and leave at currentLogIndex at current val
        if (candidates.size() >= (uint64_t) batchSize)
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Search a buffer for all the matching indices where the pattern of the given size is found.
 */
std::vector<uint>* RedPawnInputGenerator::findMatchesOfPattern(char * buff, char * colorizedBuff, int len, uint64_t base_pattern, uint64_t colorized_pattern, int compare_size)
{

    // This bool can be used to measure the impact of colorization.
    // When turned off, we only check in the original buffer and pattern
    bool doCheckColorized = true;

    std::vector<uint> *indices = new std::vector<uint>();

    // Search entire testcase for the pattern. If we find it, then if colorization checking
    // is enabled, then make sure we find the same match in the colorized data as well.
    // The colorization check can reduce matches by 99%.
    for (uint i = 0; i < (uint) len - compare_size; i++)
    {
        // Check the pattern against the base testcase
        if (memcmp((void *) (buff + i), &base_pattern, compare_size) == 0)
        {
            // Also check the colorized
            if (doCheckColorized)
            {
                if (memcmp((void *) (colorizedBuff + i), &colorized_pattern, compare_size) == 0)
                {
                    indices -> push_back(i);
                }
            } else {
                indices -> push_back(i);
            }
        }
    }
    
    return indices;
}



/**
 * @brief Add a new testcase into the redpawn candidates vector if it is unique.
 *
 * @note The improving cmplog paper showed that many RedPawn transformations end
 *       up producing identical testcases (eg reversing the byte order of all 0s).
 *       As a result, an important optimization is making sure we don't add the
 *       same testcase multiple times. This function accomplishes that by saving
 *       hashes of each testcase into the addedHashes hashtable.
 */
bool RedPawnInputGenerator::addCandidateTestcase(char * buff, int size)
{

    if (!canAddMoreTestCases())
    {
        free(buff);
        return false;
    }

    testCasesGenerated++;
    testCasesGeneratedTotal++;
    uint64_t thisHash = hashTestCase(buff, size);
    if (addedHashes.find(thisHash) == addedHashes.end())
    {
        candidates.push_back(std::make_pair(buff, size));
        addedHashes.insert(thisHash);
        testCasesAdded++;
        testCasesAddedTotal++;
    } else {
        // Free the memory of testcases that don't make it into the candidates vector
        free(buff);
    }
    return true;
}

void RedPawnInputGenerator::addCandidatesToStorage(StorageModule& storage)
{
    // All testcases in the candidates vector are unique, so we can add them all

    //LOG_INFO << "Adding " << candidates.size() << " testcases to storage.";
    for (const auto& [rp_testcase, size] : candidates)
    {
        StorageEntry * newEntry = storage.createNewEntry();
        newEntry -> allocateBuffer(testCaseKey, size);
        char * buff = newEntry -> getBufferPointer(testCaseKey);
        memcpy(buff, rp_testcase, size);
        free(rp_testcase);
    }

    candidates.clear();
}


/* @brief We can add at most twice the batchSize if they all get added from within
   the same log index.
*/
bool RedPawnInputGenerator::canAddMoreTestCases()
{
    return candidates.size() < (unsigned int) 2 * batchSize;
}

/* @brief A quick and simple hash function for testcase contents to determine
 * uniqueness. Based on FNV-1 hash.
 */
uint64_t RedPawnInputGenerator::hashTestCase(char * buff, int size)
{
    uint64_t hash = 0xcbf29ce484222325;
    uint64_t prime = 1099511628211;
    for (int i = 0; i < size; i++)
    {
        hash = hash * prime;
        hash = hash ^ buff[i];
    }
    return hash;
}


/**
 * @brief Perform a direct replacement of the given pattern and size at the provided indices.
 * Adds candidates by calling addCandidateTestCase which performs uniqueness checking.
 */
bool RedPawnInputGenerator::performPatternReplacements(char * buff, int len, std::vector<uint>* indices, uint64_t replacement, int compare_size)
{

    if (compare_size > 8)
    {
        LOG_WARNING << "Compare sizes > 8 bytes not supported yet.";
        return true;
    }

    for (uint i = 0; i < indices -> size(); i++)
    {
        uint replaceIndex = indices->at(i);

        // Create variant 1: direct copy
        char * rp_candidate = (char *) malloc(len);
        memcpy(rp_candidate, buff, len);
        memcpy(rp_candidate + replaceIndex, &replacement, compare_size);

        /*
          LOG_INFO << "Original | new";
          for (int j = 0; j < len; j++)
          {
          char string_buff[16];
          sprintf(string_buff, "%02X %02X", (unsigned char) buff[j], (unsigned char) rp_candidate[j]);
          LOG_INFO << string_buff;
          }
        */
    
        bool success = addCandidateTestcase(rp_candidate, len);
        if (!success)
            return false;
    }
    return true;
}

/**
 * @brief Perform a direct replacement of the given pattern and size at the provided indices.
 * Adds candidates by calling addCandidateTestCase which performs uniqueness checking.
 */
bool RedPawnInputGenerator::performPatternReplacement(char * buff, int len, int index, uint64_t replacement, int compare_size)
{

    if (compare_size > 8)
    {
        LOG_INFO << "Warn: compare sizes > 8 not supported yet.";
        return true;
    }

    // LOG_INFO << "Replacing " << compare_size << " bytes as index " << index << " with " << replacement;
    char * rp_candidate = (char *) malloc(len);
    memcpy(rp_candidate, buff, len);
    memcpy(rp_candidate + index, &replacement, compare_size);

    /*
    LOG_INFO << "Original | new";
    for (int j = 0; j < len; j++)
    {
        char string_buff[16];
        sprintf(string_buff, "%02X %02X", (unsigned char) buff[j], (unsigned char) rp_candidate[j]);
        LOG_INFO << string_buff;
    }
    */

    return addCandidateTestcase(rp_candidate, len);
}


// Helper function for colorize debugging
/*
std::string printTestCase(char * buffer, int size, int start, int end)
{
    std::string outString;
    int i;
    for (i = 0; i < size; i++)
    {
        if (i == start)
            outString += "[";
        if (i == end)
            outString += "]";
    
        outString += buffer[i];
    }
    if (i == end)
        outString += "]";
    return outString;
}
*/

 /**
  * @brief The goal of colorize is to generate a seed that is as unique as possible 
  *  but still “the same” as the original, to get a poor engineer’s taint tracking cheaply. 
  *  A colorized version is “the same as” the original if the coverage map is the same and
  *  its within 2x of the speed.
  * 
  * @note The algorithm is covered on pg 7 of the RedQueen paper. The short version is that 
  *  it uses a max heap (by size), randomizes the largest chunk, fuzzing that test seed. 
  *  If the results aren’t “the same as” the original, it divides it in two and pushes 
  *  them on the max heap and resets that section of the test seed. If it succeeds,
  *  it saves it and grabs the next largest section. It repeats until either the heap 
  *  is empty or the limit is hit. Redqueen gave it a 1000 tries to converge, which is the
  *  default value for colorizeMaxExecs although it can be configured by user.
  */
bool RedPawnInputGenerator::colorize(StorageModule& storage, StorageEntry * baseEntry, int size, char * colorized_testcase)
{

    taintRegions.clear();

    // Requires a testcase with at least 1 byte
    if (size < 1)
    {
        return false;
    }

    // Load information about the base testcase
    char * base_testcase = baseEntry -> getBufferPointer(testCaseKey);

    if (baseEntry -> getBufferSize(traceBitsKey) == -1)
    {
        throw RuntimeException("A testcase did not have trace bits. Did you forget to set alwaysSaveTraceBits in your executor?", RuntimeException::CONFIGURATION_ERROR);
    }

    int traceBitsSize = baseEntry -> getBufferSize(traceBitsKey);
    char * baseTraceBits = baseEntry -> getBufferPointer(traceBitsKey);
    int baseExecTime = baseEntry -> getIntValue(execTimeKey);

    // The format for ranges is (width of range, (start of range, end of range))
    // Width first makes the priority queue (max heap) sorted by size which we want
    std::pair<int, std::pair<int, int>> starting_range(size, std::make_pair(0, size-1));

    // Create max heap and initialize with entire range
    std::priority_queue<std::pair<int, std::pair<int, int>> > uncolorized_sections;
    uncolorized_sections.push(starting_range);

    // Create workspace buffer that contains colorized state
    char* dev_buffer = (char*) calloc(size, sizeof(char));
    memcpy(dev_buffer, base_testcase, size);

    // Process largest chunk at a time until no more chunks or we hit max iteration count
    bool converged = false;
    int iterations = 0;
    bool colorization_failed = false;
    while(!uncolorized_sections.empty() && iterations < colorizeMaxExecs)
    {
        // Get biggest uncolorized range
        std::pair<int, std::pair<int, int>> curr_heap_entry = uncolorized_sections.top();
        uncolorized_sections.pop();

        // LOG_DEBUG << "Colorize step " << (iterations + 1) << " operating on range: " << curr_heap_entry;

        // Break down the heap entry
        int curr_range_size  = curr_heap_entry.first;
        int curr_range_start = curr_heap_entry.second.first;
        int curr_range_end   = curr_heap_entry.second.second;

        // LOG_DEBUG << printTestCase(dev_buffer, size, curr_range_start, curr_range_start + curr_range_size);

        // Copy random bytes onto the targeted range
        getUniformlyRandomBytes(dev_buffer + curr_range_start, curr_range_size);

        // Run the new testcase with the randomized bytes to see how it behaves
        StorageEntry * testEntry = storage.createLocalEntry();
        testEntry -> allocateAndCopyBuffer(testCaseKey, size, dev_buffer);

        regular_executor->runTestCase(storage, testEntry);

        // Inspect traces to see if it behaved the same
        if (testEntry -> getBufferSize(traceBitsKey) == -1)
        {
            throw RuntimeException("A testcase did not have trace bits. Did you forget to set alwaysSaveTraceBits in your executor?", RuntimeException::CONFIGURATION_ERROR);
        }
        char * testTraceBits = testEntry -> getBufferPointer(traceBitsKey);
        int thisExecTime = testEntry -> getIntValue(execTimeKey);

        // A testcase is "the same" as the original if it has the same coverage map
        // and the execution time is within a factor of 2.
        if ((memcmp(baseTraceBits, testTraceBits, traceBitsSize) == 0) &&
            (thisExecTime < 2 * baseExecTime))
        {
            // If testcase is the same, we keep these changes and continue onto next chunk.
            taintRegions.push_back(std::make_pair(curr_range_start, curr_range_end));
        } else {

            // If testcase is not the same, we revert, split the chunk in half, and push both onto the heap

            // Revert changes by copying from original buffer into the workspace buffer
            memcpy(dev_buffer + curr_range_start, base_testcase + curr_range_start, curr_range_size);
        
            // Recursion base case: can't split if down to 1 byte
            if (curr_range_size > 1)
            {
                memcpy(dev_buffer + curr_range_start, base_testcase + curr_range_start, curr_range_size);
                int midpoint = curr_range_start + curr_range_size / 2 - 1;
                int front_size = midpoint - curr_range_start + 1;
                int back_size = curr_range_end - midpoint;

                std::pair<int, std::pair<int, int>> front_half(front_size, std::make_pair(curr_range_start, midpoint));
                std::pair<int, std::pair<int, int>> back_half(back_size, std::make_pair(midpoint+1, curr_range_end));
                uncolorized_sections.push(back_half);
                uncolorized_sections.push(front_half);
            }
        }

        storage.removeLocalEntry(testEntry);
        iterations++;
    }

    converged = uncolorized_sections.empty();
    if(converged)
    {
        LOG_DEBUG << "RedPawn colorize converged in " << iterations << " steps.";
    }
    else
    {
        LOG_DEBUG << "RedPawn colorize did not converge in " << iterations << " steps.";
    }

    // Calculate how much we actually changed.
    // We compare the final buffer directly, so that accidentally replacing a value with the
    // same value randomly doesn't get counted.
    int bytes_changed = 0;
    for (int i = 0; i < size; i++)
    {
        if (base_testcase[i] != dev_buffer[i])
            bytes_changed++;
    }

    float percentChanged = bytes_changed / (float) size * 100.0;
    LOG_DEBUG << "Bytes changed: " << bytes_changed << " (" << percentChanged << "%)";

    // LOG_INFO << "Number taint regions: " << taintRegions.size();
    // Whether we converged or not, still take what randomness we can.
    memcpy(colorized_testcase, dev_buffer, size);
    free(dev_buffer);

    if (colorization_failed)
        return false;
    
    // We proceed to RedPawn analysis as long as there is at least 1 taint region to work from
    return bytes_changed > 0;
}

void RedPawnInputGenerator::printStats()
{
    static uint64_t lastPrint = 0;
    uint64_t curTime = VmfUtil::getCurTime();
    if (currTestCaseID != 0 && curTime - lastPrint > 5 * 1000 * 1000)
    {
        // Header
        LOG_INFO << "---------------------------------";

        // Testcases in Queue
        LOG_INFO << "RedPawn testcases in queue: " << testCasesInQueue;

        // Current testcase stats
        LOG_INFO << "Current testcase ID: " << currTestCaseID << ", of size: " << size;

        // How long we've been working from the same seed
        time_t now = time(0);
        int secondsSpent = difftime(now, timeStartedTestCase);
        LOG_INFO << "Seconds spent on this testcase: " << secondsSpent;

        // Testcases generated
        LOG_INFO << "Testcases generated from last seed testcase: " << testCasesAddedByLastSeed;
        LOG_INFO << "Testcases generated total: " << testCasesAddedTotal;

        // Footer
        LOG_INFO << "---------------------------------";
        lastPrint = curTime;
    }
}


/**
 * @brief get a set of uniformly random bytes using a Mersenne twister. dev/rand and others are biased
 *      towards certain numbers and our goal in colorize() is as much uniquness as possible.
 * @param size is in bytes not bits
 * @note mt based on https://gist.github.com/PhDP/5289449
 */
void RedPawnInputGenerator::getUniformlyRandomBytes(char* outbuff, int size)
{

    // Here's a trivial version based on rand().
    // More complex version using a merseinne twister below.
    /*
     for (int i = 0; i < size; i++)
     {
         outbuff[i] = rand() % 256;
     }
     return;
    */

    // Generate random bits 4-bytes at a time
    int iterations = size / 4;
    int trailing_bytes = size - iterations * 4;
    // LOG_INFO << "Iterations: " << iterations << ", trailing: " << trailing_bytes;

    // Handle multiples 4 of bytes
    for(int i = 0; i < iterations; i++)
    {
        // Generate 4 bytes of randomness and copy into buffer
        u_int32_t random_4_bytes =  uni_uint(rng);
        memcpy(outbuff + i * 4, &random_4_bytes, 4);
    }

    // Handle trailing bytes
    if (trailing_bytes > 0)
    {
        u_int32_t random_4_bytes =  uni_uint(rng);
        memcpy(outbuff + iterations * 4, &random_4_bytes, trailing_bytes);
    }
}
