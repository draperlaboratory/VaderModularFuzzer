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
#include "KleeInitialization.hpp"
#include "Logging.hpp"
#include "VaderUtil.hpp"
#include <experimental/filesystem>
#include <dirent.h>

using namespace vader;

#include "ModuleFactory.hpp"
REGISTER_MODULE(KleeInitialization);

/**
 * @brief Constructor
 * initialize the set of strings in the SUT
 * 
 * @param name the name of the module.
 */
KleeInitialization::KleeInitialization(std::string name) :
    InitializationModule(name)
{}


KleeInitialization::~KleeInitialization()
{}

/**
 * @brief builder method to support the `ModuleFactory`
 * Constructs an instance of the class, and returns a pointer to the caller.
 * 
 * @param name the name of the module.
 */
Module* KleeInitialization::build(std::string name)
{
    return new KleeInitialization(name);
}

/**
 * @brief initialization method
 * Retrieve the path to the 'sut' binary and configure klee directories.
 * 
 * @param config the ConfigInterface
 */
void KleeInitialization::init(ConfigInterface& config)
{    
    // Get location of llvm-compiled bitcode file to feed to klee
    std::string bitcodeFP = config.getStringParam(getModuleName(),"bitcodeFilePath");

    // Make sure the file exists
    if(!std::experimental::filesystem::exists(bitcodeFP))
    {
        LOG_ERROR << "Could not find bitcodeFilePath: " << bitcodeFP;
        throw RuntimeException("Specified .bc file not found", RuntimeException::CONFIGURATION_ERROR);
    }

    //check that file name has expected .bc extension
    programPath = realpath(bitcodeFP.c_str(), NULL);
    std::string checkExtension = programPath.substr(programPath.length()-3);
    if(0 != checkExtension.compare(".bc"))
    {
        LOG_ERROR << "bitcodeFilePath parameter does not have a .bc extension";
        throw RuntimeException( "Klee Initialization input not in expected format", RuntimeException::CONFIGURATION_ERROR);
    }

    // create working directory where klee will output files
    std::string outputDir = realpath(config.getOutputDir().c_str(), NULL);
    workingDirectory = outputDir + "/klee_working_dir";
    VaderUtil::createDirectory(workingDirectory.c_str());
    kleeOutputDir = workingDirectory + "/klee-last";

    // directory where binary files for test cases will go
    testCaseInputDir = outputDir + "/klee_gen_testcases";
    VaderUtil::createDirectory(testCaseInputDir.c_str());

    //Find the pre-compiled python script to process klee output
    std::string exePath = VaderUtil::getExecutablePath();
    std::string kleeScriptPath = exePath + "/process_klee_output";
    char* path = realpath(kleeScriptPath.c_str(), NULL);
    if(nullptr == path)
    {
        LOG_ERROR << "process_klee_output script not found";
        throw RuntimeException("Unable to find process_klee_output script", RuntimeException::OTHER);
    }
    kleeTool = path;
}

/**
 * @brief establish the storage needs of the Initialization
 * 
 * @param registry the StorageRegistry with which storage needs are registered.
 */
void KleeInitialization::registerStorageNeeds(StorageRegistry& registry)
{
    testCaseKey = registry.registerKey(
        "TEST_CASE",
        StorageRegistry::BUFFER,
        StorageRegistry::WRITE_ONLY
    );
}

/**
 * @brief perform the initialization step
 * Compiles SUT to LLVM bitcode, runs klee on bitcode, and uses python script to turn klee output to binary files
 * that are then turned into new test cases in storage.
 * 
 * @param storage the StorageModule with which the test cases are registered.
 */
void KleeInitialization::run(StorageModule& storage)
{
    char buffer[0x1000];

    //should klee be included in the build, add call to compileBitcode() here

    // RUN KLEE ON BITCODE, GENERATE KTEST OUTPUTS
    // https://klee.github.io/docs/options/
    // options based on klee-sample-generator.c's KleeGenerateSamples() from vader-training

    // By specifying the option -sym-files 1 256, 
    // we ask KLEE to provide one symbolic file of size 256 bytes, and that file is named ‘A’ by KLEE. 
    // We therefore provide this file name as an argument to our program.
    // https://klee.github.io/tutorials/using-symbolic/

    snprintf(buffer, sizeof(buffer), 
            "klee --output-dir='%s' -max-time=10 --simplify-sym-indices --libc=uclibc --posix-runtime %s A -sym-files 1 256", 
            kleeOutputDir.c_str(), programPath.c_str());
    std::cout << "BUFFER: " << buffer << "\n" << std::flush;
    if(system(buffer)!=0)
    {
        LOG_ERROR << "FAILED TO LAUNCH KLEE";
        throw RuntimeException("Unable to launch klee", RuntimeException::USAGE_ERROR);
    }

    // CREATE BINARY FILES FROM KTEST FILES
    // main argv[1] = in_dir, argv[2] = out_dir 
    // where in_dir is where klee has put .ktest files and outdir is where binary testcase files are written to
    snprintf(buffer, sizeof(buffer), "%s %s %s", kleeTool.c_str(), kleeOutputDir.c_str(), testCaseInputDir.c_str());
    if(system(buffer) != 0)
    {
        LOG_ERROR << "FAILED TO PROCESS KLEE OUTPUT";
        throw RuntimeException("Unable to process klee output", RuntimeException::USAGE_ERROR);
    }

    // TURN BINARY FILES INTO TEST CASES
    VaderUtil::createNewTestCasesFromDir(storage, testCaseKey, testCaseInputDir);

    return;
}

/**
 * @brief Intential dead code
 * Code that compiles the bitcode to feed into klee. Currently VMF requires the user to compile
 * their own bitcode manually and specify the bitcode file in the config.
 * However, we want to save this code for documentation purposes and in case we want to add
 * file compilation as a feature.
 */
void KleeInitialization::compileBitcode(void)
{
    char buffer[0x1000];

    //Before running KLEE with STP on larger benchmarks, it is essential to set the size of the stack to a very large value
    // In most cases, the hard limit will have to be increased first, so it is best to directly edit the corresponding configuration file (e.g., /etc/security/limits.conf).
    snprintf(buffer, sizeof(buffer), "ulimit -s unlimited");
    if(system(buffer) != 0)
    {
        LOG_ERROR << "FAILED TO UNLIMIT KLEE STACK SIZE";
        throw RuntimeException("Unable to unlimit the size of the klee stack", RuntimeException::USAGE_ERROR);
    }

    // CREATE LLVM BITCODE
    // vader 1.0 used `extract-bc` to extract bitcode from a .tar
    // vader 2.0 compiles program to LLVM bitcode using clang -emit-llvm (https://klee.github.io/tutorials/testing-function/)
    // NOTE: if incorporating into VMF, need to update usage of programPath & programName 
    snprintf(buffer, sizeof(buffer), 
            "cd %s && clang -I ../../include -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone %s/%s.c", 
            workingDirectory.c_str(), programPath.c_str(), programName.c_str());
    std::cout << buffer << "\n" << std::flush;
    if(system(buffer)!=0)
    {
        LOG_ERROR << "FAILED TO EXTRACT LLVM BITCODE";
        throw RuntimeException("Unable to extract llvm bitcode", RuntimeException::USAGE_ERROR);
    }
}
