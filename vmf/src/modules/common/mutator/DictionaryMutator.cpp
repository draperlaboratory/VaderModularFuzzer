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
#include <filesystem>

#include "DictionaryMutator.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(DictionaryMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* DictionaryMutator::build(std::string name)
{
    return new DictionaryMutator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void DictionaryMutator::init(ConfigInterface& config)
{
    std::string output_base = config.getOutputDir();
    dictionary_path_hardcode = output_base + "/strings.dict";
    dictionary_paths = config.getStringVectorParam(getModuleName(), "dictionaryPaths", {});

    // do not check for file existence yet as this may need to be geneated by 
    // the DictionaryInitialization module

    // Setup random number generator
    rand = VmfRand::getInstance();
}

/**
 * @brief Construct a new DictionaryMutator::DictionaryMutator object
 * 
 * @param name name of instance 
 */
DictionaryMutator::DictionaryMutator(std::string name) :
    MutatorModule(name)
{
    rand = nullptr;
}

/**
 * @brief Destroy the DictionaryMutator::DictionaryMutator object
 */
DictionaryMutator::~DictionaryMutator()
{
    for (char* token : lines) {
        LOG_DEBUG << "Deleting token: " << token;
        delete[] token;
    }
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void DictionaryMutator::registerStorageNeeds(StorageRegistry& registry)
{
}


/**
 * @brief parsing function for reading in the list of tokens for the mutator
 * 
 * @param dictionary_path Path to the list of tokens to fuzz with
 * @param lines the vector of tokens (all tokens are added to this list)
 * @throws RuntimeException if cannot open tokens list file
 * @throws RuntimeException if tokens list does not follow format
 * @throws RuntimeException if a token is blank
 */
void DictionaryMutator::get_tokens(std::string dictionary_path, std::vector<char *>& lines) {
    // read in list of strings
    std::ifstream inputFile(dictionary_path);

    if (!inputFile.is_open()) {
        throw RuntimeException("Failed to open strings file", RuntimeException::USAGE_ERROR);
    }

    std::string line;

    while (std::getline(inputFile, line)) {
        if (line.empty()) {
            // ignore blank lines
            continue;
        } else {
            if (line.front() == '#') {
                // ignore comment lines
                continue;
            }

            // Find start of 
            size_t start = line.find("\"");
            if (start == std::string::npos) {
                LOG_ERROR << "Misformated token line missing opening double quote: '" << line << "'";
                throw RuntimeException("Misformated token line missing opening double quote", RuntimeException::USAGE_ERROR);
            }
            start += 1; // remove double quote
            
            std::string remainder = line.substr(start); 
            size_t end = remainder.rfind("\"");
            if (end == std::string::npos) {
                LOG_ERROR << "Misformated token line missing closing double quote: '" << line << "'";
                throw RuntimeException("Misformated token line missing closing double quote", RuntimeException::USAGE_ERROR);
            }
            end -= 1; // remove double quote
            end += start; // re-calculate index into original string

            if ((end - start + 1) > 0) {
                // ignore double quotes surrounding tokens
                LOG_DEBUG << "Allocating " << end - start + 1 << " bytes for: " << line.substr(start, end - start + 1);
                char* token = new char[end - start + 2];
                std::strcpy(token, line.substr(start, end - start + 1).c_str());
                lines.push_back(token);
            } else {
                LOG_ERROR << "Blank token for line: '" << line << "' in " << dictionary_path
                    << " (start: " << start << ", end: "<< end << " line: '"<< line <<"')"; 
                throw RuntimeException("Blank token", RuntimeException::USAGE_ERROR);
            }
        }
    }
    inputFile.close();
}

/**
 * @brief Load in the list of tokens provided by the user
 * 
 * @throws RuntimeException if token list is empty.
 */
void DictionaryMutator::initialize_lines() {
    if (std::filesystem::exists(dictionary_path_hardcode)) {
        LOG_INFO << "Loading hard-coded dictionary path: " << dictionary_path_hardcode;
        get_tokens(dictionary_path_hardcode, lines);
    }

    for ( std::string dictionary_path : dictionary_paths) {
        LOG_DEBUG << "Reading in tokens file: " << dictionary_path; 
        get_tokens(dictionary_path, lines);
    }

    if (lines.size() == 0) {
        LOG_ERROR << "Blank list of tokens after load.";
        throw RuntimeException("Blank token list", RuntimeException::USAGE_ERROR);
    }
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * Creates a new StorageEntry containing a modified test case buffer.
 * 
 * Mutation will take a list of tokens provided by the YAML configuration and 
 * randomly insert them into the baseEntry buffer copy.  Mutation will cause 
 * buffer expansion.  This method will lazily load the input dictionary of 
 * tokens provided as identified by the configuration file.
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @param newEntry the test case to write to
 * @param testCaseKey the field to write to in the new entry
 * @throws RuntimeException if baseEntry has an empty test case buffer.
 */
void DictionaryMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int inputSize = baseEntry->getBufferSize(testCaseKey);

    if (inputSize <= 0) 
    {
	    throw RuntimeException("DictionaryMutator mutate called with zero sized buffer",
	          RuntimeException::USAGE_ERROR);
    }

    //Allocate the new test case buffer (here we go ahead and also copy what was in the baseEntry)
    char* inputBuffer = baseEntry->getBufferPointer(testCaseKey);

    if (lines.empty()) {
        initialize_lines();
    }

    // Take a random string from the list of tokens
    uint64_t randLineIdx = rand->randBelow((int)lines.size());
    uint64_t randBuffIdx = rand->randBelow(inputSize);

    // Mutate the test case
    size_t token_size = std::strlen(lines[randLineIdx]);
    size_t outputSize = token_size + inputSize;
    LOG_DEBUG << "Outputting new testcase of size " << outputSize;
    char* outputBuffer = newEntry->allocateBuffer(testCaseKey, (int)outputSize);
    memcpy(outputBuffer, inputBuffer, randBuffIdx);
    memcpy(
        (outputBuffer + randBuffIdx), 
        lines[randLineIdx], 
        token_size
    );
    memcpy(
        (outputBuffer + randBuffIdx + token_size), 
        (inputBuffer + randBuffIdx), 
        (outputSize - randBuffIdx - token_size)
    );
}

