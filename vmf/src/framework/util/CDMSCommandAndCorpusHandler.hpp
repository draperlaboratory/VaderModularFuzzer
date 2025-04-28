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
#pragma once
#include "ConfigInterface.hpp"
#include "StorageModule.hpp"
#include "ControllerModule.hpp"
#include "json11.hpp"
#include <string>
#include <chrono>
#include <filesystem>

namespace vmf
{

/**
 * @brief Helper class for command and corpus handling for interacting with CDMS
 * This is a singleton class.  By convention, the init method should be called only 
 * by the controller module, as the configuration options for this module are part
 * of the controller config.  But all users of this module should call register
 * storage needs to accurated reflect their storage usage.
 * 
 * When running in distributed mode, this class will regulate the flow of new tests
 * from the server into the fuzzer (to avoid a large memory spike if many test cases are
 * read in at once).  It tags all test cases that came from the server with the SERVER_TC
 * tag, so that other modules can avoid sending these test cases back to the server.
 * @image html CoreModuleDataModel_9.png width=800px
 * @image latex CoreModuleDataModel_9.png width=6in
 */
class CDMSCommandAndCorpusHandler
{
public:
    static CDMSCommandAndCorpusHandler& getInstance();

    ~CDMSCommandAndCorpusHandler();
    /// deleted to enforce the singleton pattern
    CDMSCommandAndCorpusHandler(CDMSCommandAndCorpusHandler const &) = delete;
    /// deleted to enforce the singleton pattern
    void operator=(CDMSCommandAndCorpusHandler const &) = delete;

    void init(ConfigInterface& config, std::string parentControllerName);
    void registerStorageNeeds(StorageRegistry& registry);
    void handleCommand(StorageModule& storage, bool isDistributed, ControllerModule::ControllerCmdType cmd);
    bool loadCorpusInitialSeeds(StorageModule& storage, std::string tags, bool getMinCorpus);
    bool loadWholeCorpus(StorageModule& storage, std::string tags, int fileURLKey);
    bool hasMoreFilesToLoad();
    void clearAnyInProgessLoading();

private:
    CDMSCommandAndCorpusHandler();
    int unzipJsonZipFiles(json11::Json json);
    bool loadTestCasesUpToBatchSize(StorageModule& storage);
    void clearInternalVariables();
   
    enum state
    {
        IDLE,
        LOADING_SEEDS,
        LOADING_WHOLE_CORPUS,
        LOADING_CORPUS_UPDATE
    };

    /// The current state of this class (i.e. whether or not we are in the middle of something, and what that thing is)
    state myState;

    /// The configured batch size (number of new test cases that can be loaded at once)
    int batchSize;

    ///The working directory for zip files coming from the server
    std::string workingDir;

    ///The path to a temporary directory to unzip into
    std::string zipOutPath;

    ///The list of files to read in (from the zip files)
    std::vector<std::filesystem::directory_entry> filesToRead;

    //The current index into the filesToRead vector
    int currentFileIndex;
    
    /// The list of tags that the controller is interested in
    std::string corpusUpdateTags;

    /// The server test case tag handle, used to tag test cases that are incoming from the server
    int serverTestCaseTag;

    /// The test case handle, use to write test cases 
    int testCaseKey;

    /// The server file name handle (or -1 if this is not being written currently)
    int fileNameKey;

    /// The number of minutes that must pass before the initial corpus synchronization between fuzzer instances
    int corpusInitialUpdateMins;

    /// The minimum number of minutes that must pass before accepting another corpus update command on a continuous basis
    int corpusUpdateRateMins;

    /// The timestamp of the last corpus update
    std::chrono::system_clock::time_point lastCorpusUpdate;

    /// Flag determining if the initial corpus update has been completed
    bool initialCorpusSyncComplete;
};
}