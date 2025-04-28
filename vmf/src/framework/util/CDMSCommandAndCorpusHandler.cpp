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
#include "CDMSCommandAndCorpusHandler.hpp"
#include "Logging.hpp"
#include "CDMSClient.hpp"
#include "VmfUtil.hpp"
#include "OSAPI.hpp"
#include <vector>
#include <filesystem>

using namespace vmf;
namespace fs = std::filesystem;

/**
 * @brief Accessor for the singleton CDMSCommandAndCorpusHandler
 * 
 * @return CDMSCommandAndCorpusHandler& the singleton
 */
CDMSCommandAndCorpusHandler& CDMSCommandAndCorpusHandler::getInstance() {
    static CDMSCommandAndCorpusHandler instance;
    return instance;
}

CDMSCommandAndCorpusHandler::CDMSCommandAndCorpusHandler()
{
    myState = IDLE;
    currentFileIndex = 0;
    fileNameKey = -1;
    initialCorpusSyncComplete = false;

    //These should be initialized in init/config
    batchSize = 0;
    corpusInitialUpdateMins = 0;
    corpusUpdateRateMins = 0;
    serverTestCaseTag = 0;
    testCaseKey = 0;

}

CDMSCommandAndCorpusHandler::~CDMSCommandAndCorpusHandler()
{

}

/**
 * @brief Initialize this helper class, including reading in any configuration options
 * Note that the configuration options for this class are listed under the parent controller object.
 * This should be called as part of the parent controller's own initialization.
 * @param config the config interface to read from
 * @param parentControllerName the parent controller name (as this is how any config options are stored)
 */
void CDMSCommandAndCorpusHandler::init(ConfigInterface& config, std::string parentControllerName)
{
    //Note: These parameters are really only needed for distributed fuzzing mode
    lastCorpusUpdate = std::chrono::system_clock::now();
    initialCorpusSyncComplete = false;
    batchSize = config.getIntParam(parentControllerName,"batchSize",1000);
    corpusUpdateRateMins = config.getIntParam(parentControllerName,"corpusUpdateRateMins", 5);
    corpusInitialUpdateMins = config.getIntParam(parentControllerName, "corpusInitialUpdateMins", 5);
    if(corpusUpdateRateMins<1)
    {
        LOG_WARNING << "Distributed Fuzzing -- Minimum corpus update increased to 1 minute";
        corpusUpdateRateMins = 1;
    }
    LOG_INFO << "Distributed Fuzzing -- Minimum corpus update rate is " << corpusUpdateRateMins;

    if(corpusInitialUpdateMins<1)
    {
        LOG_WARNING << "Distributed Fuzzing -- Initial corpus update time increased to 1 minute";
        corpusInitialUpdateMins = 1;
    }
    LOG_INFO << "Distributed Fuzzing -- Initial corpus update time is " << corpusInitialUpdateMins <<
                " with batch size of " << batchSize;

    std::vector<std::string> defaultTags = {"RAN_SUCCESSFULLY"};
    std::vector<std::string> updateTags = config.getStringVectorParam(parentControllerName,"corpusUpdateTags", defaultTags);
    corpusUpdateTags = CDMSClient::getInstance()->formatTagList(updateTags);
    LOG_INFO << "Distributed Fuzzing -- Corpus update will retrieve tags=" << corpusUpdateTags;

    //Create a working directory for working with zip files
    workingDir = config.getOutputDir() + "/tmp_zipinput";
    VmfUtil::createDirectory(workingDir.c_str());
    zipOutPath = workingDir + "/unzip_out";
}

/**
 * @brief Register the storage needs for this helper class
 * This should be called as part of the parent controller's storage registration.
 * @param registry the StorageRegistry object
 */
void CDMSCommandAndCorpusHandler::registerStorageNeeds(StorageRegistry& registry)
{
   serverTestCaseTag = registry.registerTag("SERVER_TC", StorageRegistry::WRITE_ONLY);
   testCaseKey = registry.registerKey("TEST_CASE", StorageRegistry::BUFFER, StorageRegistry::WRITE_ONLY);
   fileNameKey = -1; //This is only used when a module calling this method register for the key and askes that it be written
}

/**
 * @brief Perform command handling for the controller
 * This method only has an effect in distributed mode.  In distributed mode, if the received command 
 * is NEW_CORPUS, then a corpus update will be performed (provided enough time has passed and we are
 * not still processing prior additions to the corpus).  When the command is NONE, this class may still
 * add additional entries to storage, if there were more than batchSize entries loaded previously.
 * 
 * @param storage the StorageModule to use
 * @param isDistributed true if VMF is running in distributed mode
 * @param cmd the command to process
 */
void CDMSCommandAndCorpusHandler::handleCommand(StorageModule& storage, bool isDistributed, ControllerModule::ControllerCmdType cmd)
{
    if(isDistributed)
    {
        //If the state is non-IDLE, then we are in the middle of loading corpus data
        //and can't process a NEW_CORPUS command
        if((ControllerModule::ControllerCmdType::NONE == cmd) || (IDLE != myState))
        {
            if(IDLE != myState)
            {
                bool hasMore = loadTestCasesUpToBatchSize(storage);
                if(!hasMore)
                {
                    //Transition to the IDLE state once all of the test cases have been loaded
                    myState = IDLE;
                }
            }
        }
        else if(ControllerModule::ControllerCmdType::NEW_CORPUS == cmd)
        {
            //Determine how long it has been since the last corpus update
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed = now - lastCorpusUpdate;
            int elapsedMin = (int)elapsed.count()/60;

            //See if enough time has passed that we should perform a corpus update
            int threshold = corpusUpdateRateMins;
            if(!initialCorpusSyncComplete){
                //Use a different time threshold for the first corpus update
                threshold = corpusInitialUpdateMins;
            }
            if(elapsedMin >= threshold)
            {
                LOG_INFO << "Performing corpus update.";
                CDMSClient* client = CDMSClient::getInstance();
                initialCorpusSyncComplete = true;
                lastCorpusUpdate = now;
                json11::Json json = client->getCorpusUpdates(corpusUpdateTags);
                unzipJsonZipFiles(json);
                bool hasMore = loadTestCasesUpToBatchSize(storage);
                if(hasMore)
                {
                    //If there is more to load, change the state to an in-progress state
                    myState = LOADING_CORPUS_UPDATE;
                }

                //A new test case is created for each test case on the file list, with the
                //"SERVER_TC" tag set so it is flagged as coming from the server
                //createNewTestCasesFromJson(storage, json, testCaseKey, serverTestCaseTag);
            }
        }
        else
        {
            LOG_ERROR << "Unknown command type: " << cmd;
        }
    }
}

/**
 * @brief Loads the initial corpus seeds from the server.
 * The seeds will only be loaded up to the configured batch size.  Any leftover test cases
 * will be loaded in a subsequent pass through the fuzzing loop.  The list of provided tags
 * will be used to filter which test cases are returned from the server -- only test cases with
 * these tags will be retrieved.  If the getMinCorpus flag is set the server will be asked to 
 * retrieve the most recent minimized corpus (if there is one). When false, the server will 
 * instead only return the initial seeds for the scenario.
 * 
 * @param storage the StorageModule
 * @param tags the list of tags for the server to filter test cases with (formatted using CDMSClient::getInstance()->formatTagList)
 * @param getMinCorpus when true, retrieve the minimized corpus if there is one (when false, only
 * the initial seeds will be retrieved)
 * @return true if this operate was successful, false otherwise
 */
bool CDMSCommandAndCorpusHandler::loadCorpusInitialSeeds(StorageModule& storage, std::string tags, bool getMinCorpus)
{
    bool done = false;
    if(IDLE == myState)
    {
        CDMSClient* client = CDMSClient::getInstance();
        json11::Json json = client->getCorpusInitialSeeds(tags, getMinCorpus);
        int count = unzipJsonZipFiles(json);
        bool hasMore = loadTestCasesUpToBatchSize(storage);
        if(hasMore)
        {
            //If there is more to load, change the state to an in-progress state
            myState = LOADING_SEEDS;
        }

        done = (count > 0); //This was successful if at least one test case was loaded
    }
    else
    {
        //This shouldn't happen, but is possible if two initialization modules are configured at once
        LOG_ERROR << "Request to load corpus initial seeds, but current state is not idle.  State=" << myState;
    }
    return done;
}

/**
 * @brief Loads the whole corpus from the server.
 * The corpus will only be loaded up to the configured batch size.  Any leftover test cases
 * will be loaded in a subsequent pass through the fuzzing loop.  If the fileURLKey is set
 * then the test cases will write the filename of each corpus file to storage.
 * 
 * @param storage the storage module
 * @param tags the list of tags for the server to filter test cases with (formatted using CDMSClient::getInstance()->formatTagList)
 * @param fileURLKey the handle to the file URL, or -1 if this field should not be used.
 * @return true if this operate was successful, false otherwise
 */
bool CDMSCommandAndCorpusHandler::loadWholeCorpus(StorageModule& storage, std::string tags, int fileURLKey)
{
    bool done = false;
    if(IDLE == myState)
    {

        CDMSClient* client = CDMSClient::getInstance();
        json11::Json json = client->getCorpus(tags);

        fileNameKey = fileURLKey; //set the file name key so the file name will be written (if it was set)
        int count = unzipJsonZipFiles(json);
        bool hasMore = loadTestCasesUpToBatchSize(storage);
        if(hasMore)
        {
            //If there is more to load, change the state to an in-progress state
            myState = LOADING_WHOLE_CORPUS;
        }

        //createNewTestCasesFromJson(storage, json, testCaseKey, serverTestCaseTag);
        done = (count > 0); //This was successful if at least one test case was loaded
    }
    else
    {
        //This shouldn't happen, but is possible if two initialization modules are configured at once
        LOG_ERROR << "Request to load whole corpus, but current state is not idle.  State=" << myState;
    }
    return done;
}

/**
 * @brief Helper method to unzip all of the zip files provided in the json structure
 * All of the files will be downloaded from the server, unzipped into the zipOutPath location, 
 * and each file will be added to the filesToRead vector.
 * 
 * @param json the json list of zip files from the server
 * @return int the number of files added to the filesToRead vector.
 */
int CDMSCommandAndCorpusHandler::unzipJsonZipFiles(json11::Json json)
{
    auto fileList    = json["files"].array_items();
    int  size        = (int) fileList.size();
    int  count       = 0;

    CDMSClient* client = CDMSClient::getInstance();

    std::string tmpFile     = "tmp_unzip.zip";
    std::string zipFilePath = workingDir + "/" + tmpFile;

    for(int i=0; i<size; i++)
    {
        auto fileJson = fileList[i];
        LOG_DEBUG << "Getting Corpus Zip File from URL: " << fileJson.string_value();

        //Retrieve zip file from server and write it to disk
        std::string     contents    = client->getCorpusFile(fileJson.string_value());  

        const char*     contentBuff = contents.data();

        VmfUtil::writeBufferToFile(workingDir, tmpFile, contentBuff, (int) contents.length());

        //Now unzip to the output directory
        OSAPI::instance().commandLineUnzip(zipFilePath, zipOutPath);

        //And load the list of files to read into a vector
        for (const auto& file : fs::directory_iterator(zipOutPath))
        {
        
            if (fs::exists(file))
            {
                filesToRead.push_back(file);
                count++;
            }
            else
            {
                //This shouldn't happen
                LOG_ERROR << "Unable to open input file" << file;
                throw RuntimeException("Unable to open input file", RuntimeException::UNEXPECTED_ERROR);
            }
        }

        //And remove the temp zip file
        std::filesystem::remove(zipFilePath);
    }

    LOG_INFO << "Retrieved new test cases from the server; " << count 
             << "; (From " << size << " zip files)";

    return count;
}

/**
 * @brief Loads up to batchSize test cases into storage from the filesToReadVector
 * If all of the files have been read, the filesToReadVector and the currentFileIndex will
 * be cleared.
 * 
 * @param storage the storage module to load the test cases into
 * @return true if there are more test cases to read
 * @return false if all the test cases have been read in
 */
bool CDMSCommandAndCorpusHandler::loadTestCasesUpToBatchSize(StorageModule& storage)
{
    bool hasMoreTestCases = false;
    //This can be 0, if the server sends a zip file with no test cases in it
    if(filesToRead.size() > 0) 
    {
        //Read up the batchSize or the remaining number of files, whichever is smaller
        int filesRemaining = (int) filesToRead.size() - currentFileIndex;
        int max = batchSize;
        if(filesRemaining < max)
        {
            max = filesRemaining;
            hasMoreTestCases = false;
        }

        for(int i=currentFileIndex; i<max; i++)
        {
            std::filesystem::directory_entry file = filesToRead[i];

            // open and read file into buffer
            int filesize = (int) fs::file_size(file);
            std::ifstream inFile;
            inFile.open(file.path(), std::ifstream::binary);

            StorageEntry* newEntry = storage.createNewEntry();
            char* buff = newEntry->allocateBuffer(testCaseKey, filesize);
            inFile.read(buff, filesize);

            //Always add the server test case tag
            newEntry->addTag(serverTestCaseTag); 
            //Only add the filenameKey if it was set
            if(-1 != fileNameKey)
            {
                std::string name = file.path().filename().string();
                char* nameBuff = newEntry->allocateBuffer(fileNameKey, (int) name.length());
                name.copy(nameBuff,name.length());
            }
            
        }
        currentFileIndex += max;
        LOG_DEBUG << "Loaded " << max << " new test cases from the server";
    }

    if (!hasMoreTestCases)
    {
        clearInternalVariables();
    }

    return hasMoreTestCases;
}

/**
 * @brief Helper method to indicate whether or not there are more test cases that still need to be loaded
 * This is useful for controllers that want to keep running long enough for all test cases to be loaded.
 * 
 * @return true there are more test cases to load
 * @return false everything has been loaded
 */
bool CDMSCommandAndCorpusHandler::hasMoreFilesToLoad()
{
    bool moreToLoad = false;
    if(myState != IDLE)
    {
        //Any state other than IDLE indicates we are in the middle of processing
        moreToLoad = true;
    }
    return moreToLoad;
}

/**
 * @brief Aborts any in progress loading of test cases
 * This is useful for distributed fuzzing, where we need to retask VMF because of
 * server commanding.
 */
void CDMSCommandAndCorpusHandler::clearAnyInProgessLoading()
{
    if(myState!=IDLE)
    {
        LOG_INFO << "Aborting in progress loading of test cases.";
        clearInternalVariables();
        myState = IDLE;
    }
}

/**
 * @brief Helper method to clear the state variables associated with in progress data load
 * This includes clearing the temporary directory that contains zip files.
 */
void CDMSCommandAndCorpusHandler::clearInternalVariables()
{
    //Clear the output directory and the zip file
    std::filesystem::remove_all(zipOutPath);
    //Reset the data structures tracking the files
    filesToRead.clear();
    currentFileIndex = 0;
    fileNameKey = -1; //Clear the file name key
}