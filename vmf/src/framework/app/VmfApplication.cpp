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
#include "VmfApplication.hpp"
#include "CDMSClient.hpp"
#include "json11.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include "VmfRand.hpp"
#include "OSAPI.hpp"
#include <fstream>  
#include <thread> //for sleep
#include <random> //for random sleep time
#include <limits.h>

using namespace vmf;

/**
 * @brief Construct a new VMF Application
 * 
 */
VmfApplication::VmfApplication()
{
    //These will be overwritten when config is read
    taskingSleepTime = std::chrono::milliseconds(0);
}


/**
 * @brief Destroy the VMF Application
 * 
 */

VmfApplication::~VmfApplication()
{
    if(nullptr != myRegistry)
    {
        delete myRegistry;
    }

    if(nullptr != myMetadataRegistry)
    {
        delete myMetadataRegistry;
    }

    if(nullptr != myConfig)
    {
        delete myConfig;
    }
    myModuleManager.deleteModules();
}


/**
 * @brief Initializes VMF application, including parsing command line params
 * 
 * @param argc 
 * @param argv 
 * @return true if initialization was successful
 * @return false otherwise
 */

bool VmfApplication::init(int argc, char** argv)
{
    Logging::initConsoleLog(); //Console log is initialized before reading config

    bool valid = parseConfigParams(argc, argv);

    if(valid)
    {
        if(true == distributedMode)
        {
            valid = serverInit();
        }
        else
        {
            valid = localInit();
        }
    }

    return valid;
}

/**
 * @brief Helper method to perform local initialiation
 *
 * Read the config files, create the output directory, and save a copy of the
 * config files to the output directory
 *
 * @return true if initialization succeeds, false otherwise
 */

bool VmfApplication::localInit()
{
    LOG_INFO << "Initializing VMF " << VERSION_NUMBER << " in standalone mode";

    //Read in the config file
    myConfig = new ConfigManager(configFiles, &myModuleManager);
    myConfig->readConfig();

    //Create the timestamp based output directory
    std::string outputDir = createOutputDir();

    //Initialize logger
    Logging::init(*myConfig);

    //Load the vmf plugins
    loadPlugins();

    //First save a copy of config to output directory
    LOG_INFO << "Writing a copy of full config to: " << outputDir;
    myConfig->writeConfig(outputDir);

    //Load and initialize the modules in the fuzzer
    //Throws an exception if there is anything wrong with the config file
    loadAndInitModules();

    return true;
}

/**
 * @brief Helper method for server based initialization
 *
 * @return true if initialization succeeds, false otherwise
 */
bool VmfApplication::serverInit()
{
    LOG_INFO << "Initializing VMF " << VERSION_NUMBER << " in distributed mode";

    bool valid = false;
    std::string name;
    std::string outputDir;
    int pid = OSAPI::instance().getProcessID();
 
    //1. Load initial server config
    //This will only contain the configuration parameters needed to establish a connection with the server
    this->myConfig = new ConfigManager(configFiles, &myModuleManager);

    this->myConfig->readConfig();
    
    //Create the timestamp based output directory, and write it's path to myConfig
    outputDir = createOutputDir();

    //2. Initialize the distributed logger
    Logging::init(*myConfig);

    //3. Load the plugins
    loadPlugins();

    //4. Read in server parameters from config file. Initialize the CDMSClient.
    CDMSClient* client = CDMSClient::getInstance();

    name = this->myConfig->getStringParam(myConfig->VMF_DISTRIBUTED_KEY,"clientName","VMF_instance");
    int sleepTime = this->myConfig->getIntParam(myConfig->VMF_DISTRIBUTED_KEY, "taskingPollRate", 10000); //10s
    taskingSleepTime = std::chrono::milliseconds(sleepTime);

    //This allows the insertion of an initial random delay of up to the specified sleep time.
    //This prevents all the VMFs from polling for tasking synchronously.
    //Set to -1 to disable this initial delay completely
    int taskingInitialRandomDelayMax = this->myConfig->getIntParam(myConfig->VMF_DISTRIBUTED_KEY,"taskingInitialRandomDelayMax", -1); //disabled
    
    //5. Initialize interface to CDMS server
    std::string hostname = OSAPI::instance().getHostname();
    LOG_INFO << "Initializing CDMS Client.  pid=" << pid << ", hostname=" << hostname << ", name=" << name;
    client->init(*(this->myConfig), pid, name, hostname);

    //6. Register with server
    bool registered = CDMSClient::getInstance()->sendRegistration(false);
    if(!registered)
    {
        //Sending the registration message failed
        LOG_ERROR << "Registration with server failed";
        throw new RuntimeException("Unable to register with server",RuntimeException::SERVER_ERROR);
    }
    valid = true;

    //Note: myState is not updated to RUNNING as the VMF does not yet have tasking
    //For distributed fuzzing, this occurs in the run loop
    myState = WAITING_FOR_TASKING;

    if(taskingInitialRandomDelayMax > 0)
    {
        //Sleep for sometime between 0 and taskingInitialRandomDelayMax milliseconds
        std::mt19937_64 eng{std::random_device{}()};
        std::uniform_int_distribution<> dist{0, taskingInitialRandomDelayMax};
        int delay = dist(eng);
        int delaySecs = delay / 1000;
        LOG_INFO << "Sleeping for " << delaySecs << " to prevent synchronous server requests";
        std::this_thread::sleep_for(std::chrono::milliseconds{delay});
    }

    return valid;
}

/**
 * @brief Helper method to poll for tasking from the vmf server
 * @returns true if valid tasking is received, false otherwise
 * @throws RuntimeException if any critical errors are encountered
 */
bool VmfApplication::pollForTasking()
{
    bool valid = false;
    json11::Json json = nullptr;
    CDMSClient* client = CDMSClient::getInstance();

    json = client->getTasking();

    if(json != nullptr)
    {
        LOG_INFO << "Tasking received: unique id=" << client->getUniqueId() << ", scenario id =" << client->getScenarioId();
    
        //Load the config files associated with the tasking
        for (unsigned long i = 0; i < json["files"].array_items().size(); i++)
        {
            auto fileJson    = json["files"].array_items()[i];
            std::string yaml =  client->getConfigFile(fileJson.string_value());

            LOG_INFO << "Adding config file from URL: " << fileJson.string_value();

            myConfig->addConfig(yaml);
        }
        myConfig->parseConfig();
    
        LOG_INFO << "Loading and initializing VMF modules";

        //Now initialize the specified modules
        
        //First save a copy of config to output directory
        std::string outputDir = myConfig->getOutputDir();
        LOG_INFO << "Writing a copy of full config to: " << outputDir;
        myConfig->writeConfig(outputDir);

        //Now load the modules
        loadAndInitModules();

        valid = true;
        
    }

    return valid;
}

/**
 * @brief Helper method to load and initialize the modules in the configuration file
 * 
 * This includes loaded all of the modules, constructing the StorageRegistry,
 * having all modules register their storage needs, and validating the storage registration.
 * 
 * @throws RuntimeException if there is anything wrong with the configuration file or if
 * the storage registration is invalid in any way
 */
void VmfApplication::loadAndInitModules()
{
    //Call upon the ConfigManager to load and initialize all modules
    myConfig->loadModules(); //RuntimeException will be thrown if config file is invalid or modules can't be built
    myModuleManager.initializeModules(*myConfig); //Call init on every module (including storage)

    //Read the storage configuration parameters in order to initialize the StorageRegistry
    Module* storageModule = myModuleManager.getStorageModule();
    std::string storageName = storageModule->getModuleName();
    std::string sortByKey  = myConfig->getStringParam(storageName,"sortByKey",  "FITNESS");
    std::string sortByType = myConfig->getStringParam(storageName,"sortByType", "FLOAT");
    std::string sortOrder  = myConfig->getStringParam(storageName,"sortOrder",  "DESCENDING");

    LOG_INFO << "Initializing storage with sort by key " << sortByKey << " and sort order " << sortOrder;

    StorageRegistry::storageTypes type  = StorageRegistry::stringToStorageType(sortByType);
    StorageRegistry::sortOrder    order = StorageRegistry::stringToSortOrder(sortOrder);

    myRegistry          = new StorageRegistry(sortByKey, type, order);
    myMetadataRegistry  = new StorageRegistry();

    myModuleManager.registerModuleStorageNeeds(myRegistry, myMetadataRegistry);

    //Now validate the registration
    LOG_INFO<< "Validating primary storage registration";
    bool isValid = myRegistry->validateRegistration();

    if(!isValid)
    {
        throw RuntimeException( "Invalid storage registration",RuntimeException::CONFIGURATION_ERROR);
    }

    //Validate the metadata registration
    LOG_INFO << "Validating metadata registration";
    isValid = myMetadataRegistry->validateRegistration();

    if(!isValid)
    {
        throw RuntimeException( "Invalid metadata registration",RuntimeException::CONFIGURATION_ERROR);
    }

    //Initialize storage
    if(StorageModule::isAnInstance(storageModule))
    {
        myStorage = StorageModule::castTo(storageModule);
    }
    else
    {
        throw RuntimeException("Configuration file must specify a StorageModule under key storage",RuntimeException::CONFIGURATION_ERROR);
    }
    myStorage->configure(myRegistry, myMetadataRegistry);

    //Retrieve the controller module from config
    Module* rootModule = myModuleManager.getRootModule();

    if(ControllerModule::isAnInstance(rootModule))
    {
        myController = ControllerModule::castTo(rootModule);
    }
    else
    {
        throw RuntimeException("Configuration file must specify a ControllerModule as the root", RuntimeException::CONFIGURATION_ERROR);
    }

    //Check for seed specification
    int seed = myConfig->getIntParam(myConfig->VMF_FRAMEWORK_KEY, "seed", 0);
    if (seed != 0)
    {
        LOG_INFO << "VMF using seeded RNG, seed = " << seed;
        VmfRand::getInstance()->reproducibleInit(seed);
    }
    else
    {
        VmfRand::getInstance()->randInit();
    }

}

/**
 * @brief Helper method to clear the existing modules
 * This method is used prior to restarting the fuzzer (with new
 * or existing fuzzing).
 */
void VmfApplication::clearCurrentModules()
{
    //Shutdown all of the modules, then
    //delete all of the existing modules
    myModuleManager.shutdownModules(*myStorage);
    myModuleManager.deleteModules();
    myController = nullptr; //underlying module has already been deleted
    myStorage = nullptr; //underlying module has already been deleted

    //Delete the existing registry information
    if(nullptr != myMetadataRegistry)
    {
        delete myMetadataRegistry;
        myMetadataRegistry = nullptr;
    }

    if(nullptr != myRegistry)
    {
        delete myRegistry;
        myRegistry = nullptr;
    }

}

/**
 * @brief Helper method to create a timestamp based output directory
 * 
 * The output directory format is outputBaseDir/MMDD_HMS/<vmf_id>.
 * outputBaseDir is set in the config file.  <vmf_id> is only set when
 * fuzzing in distributed mode.
 * 
 * The directory path is set in myConfig.
 * @returns the path to the newly created timestamp based output directory
 */
std::string VmfApplication::createOutputDir()
{
    //Create output directory
    std::string outputBaseDir = myConfig->getStringParam(myConfig->VMF_FRAMEWORK_KEY,"outputBaseDir","output");

    time_t t = time(0);
    struct std::tm * now = std::localtime( &t );
    char timestamp[16];
    strftime(timestamp, sizeof(timestamp), "/%m%d_%H%M%S", now);

    std::string outputPath = outputBaseDir + timestamp;
    if(distributedMode)
    {
        int pid = OSAPI::instance().getProcessID();
        std::string pidDir = "vmf_" + std::to_string(pid);
        outputPath += "/" + pidDir;
    }

    myConfig->setOutputDir(outputPath);
    VmfUtil::createDirectory(outputBaseDir.c_str());
    VmfUtil::createDirectory(outputPath.c_str());

    return outputPath;
}

/**
 * @brief Helper method to load vmf plugins
 * 
 * Plugins are loaded from ./plugins ../plugins and any directories
 * specified in the config file in the additionalPluginsDir parameter.
 * @throws RuntimeException if no plugins directories are found
 */
void VmfApplication::loadPlugins()
{
    //Load anything in the plugins directory
    bool pluginsFound = false;
    std::string vmfDir = VmfUtil::getExecutablePath();
    std::string mainPlugins = vmfDir + "/plugins";
    if(VmfUtil::directoryExists(mainPlugins))
    {
        LOG_INFO << "Loading plugins from " << mainPlugins;
        myPluginLoader.loadAll(mainPlugins);
        pluginsFound = true;
    }
    else //try ../plugins
    {
        mainPlugins = vmfDir + "/../plugins";
        if(VmfUtil::directoryExists(mainPlugins))
        {
            LOG_INFO << "Loading plugins from " << mainPlugins;
            myPluginLoader.loadAll(mainPlugins);
            pluginsFound = true;
        }
    }

    //Load any additional specified plugins
    if(myConfig->isParam(myConfig->VMF_FRAMEWORK_KEY,"additionalPluginsDir"))
    {
        std::vector<std::string> pluginsDirs = myConfig->getStringVectorParam(myConfig->VMF_FRAMEWORK_KEY,"additionalPluginsDir");
        for(std::string dir: pluginsDirs)
        {
            myPluginLoader.loadAll(dir);
            pluginsFound = true;
        }
    }

    if(!pluginsFound)
    {
        LOG_ERROR << "No plugin directories were found (did not find ./plugins, ../plugins, or find any specified in the config file)";
        throw RuntimeException("No plugin directories were found", RuntimeException::USAGE_ERROR);
    }

}

/**
 * @brief Helper method to parse the command line parameters
 * 
 * This includes validating that required options are provided
 * 
 * @param argc 
 * @param argv 
 * @return true if the command line parsing succeeded
 * @return false otherwise
 */
bool VmfApplication::parseConfigParams(int argc, char** argv)
{
    bool configValid = false;
    bool helpMode = false;
    distributedMode = false;

    //Parse argc/argv
    for(;;)
    {
        switch(OSAPI::instance().getOption(argc, argv, "c:d:h")) //The colon indicates parameters with arguments
        {
            case 'c':
                configFiles.push_back(OSAPI::instance().getOptionArg());
                continue;
            case 'd':
                configFiles.push_back(OSAPI::instance().getOptionArg());
                distributedMode = true;
                continue;
            case 'h':
            default :
                helpMode = true;
                printUsage();
                break;

            case -1:
                break;
        }

    break;
    }

    //Validate config params
    if(configFiles.size() > 0)
    {
        configValid = true;
    }
    else if(!helpMode)
    {
        LOG_ERROR  << "No configuration files were specified";
        printUsage();
    }

    return configValid;
}

/**
* @brief Helper method to print VMF usage instructions
 * 
 */
void VmfApplication::printUsage()
{
    printf("   USAGE: vmf -c <yaml config file> \n");
    printf("       (multiple -c options may be provided)\n");
    printf("   FOR DISTRIBUTED MODE: vmf -d <yaml config file>\n");
    printf("       (in this case the config file must contain server config settings)\n");
}
 
/**
 * @brief Runs VMF (runs infinitely until shutdown is called)
 * Note: other exception types may be thrown from third party libraries
 * 
 * @throws RuntimeException if any errors are encountered
 */
void VmfApplication::run()
{
    if(distributedMode)
    {
        runDistributed();
    }
    else
    {
        runStandalone();
    }

    LOG_INFO << "----SHUTTING DOWN VMF MODULES----";
    myModuleManager.shutdownModules(*myStorage);

    LOG_INFO << "----VMF TERMINATED----";
    Logging::shutdown();
}

/**
 * @brief Helper method for standalone execution of VMF
 * Runs until the shutdown signal is received or a fatal error is encountered
 */
void VmfApplication::runStandalone()
{
    bool isFirstPass = true;

    if(nullptr == myController)
    {
        throw RuntimeException("Attempt to run uninitialized VMF application", RuntimeException::USAGE_ERROR);
    }

    while(!shutdownSignalReceived)
    {
        bool complete = myController->run(*myStorage, isFirstPass);
        if(complete)
        {
            LOG_INFO << "Controller completed fuzzing.  Shutting down";
            shutdownSignalReceived = true;
        }
        isFirstPass = false;
    }
}

/**
 * @brief Helper method to run distributed VMF
 * Runs until commanded to shutdown (or shutdown signal is externally set, e.g. Ctrl+C)
 */
void VmfApplication::runDistributed()
{
    bool isFirstPass = true;
    bool performCorpusUpdate = false;
    std::string reason = "";

    while(!shutdownSignalReceived)
    {
        //-------------Perform state-based behavior----------------
        if(RUNNING == myState)
        {
            //Run the normal fuzzing loop
            doRunningState(reason,performCorpusUpdate,isFirstPass);

            isFirstPass = false;
            performCorpusUpdate = false;

        }
        else if(RESTARTING == myState)
        {
            //Restart with the current tasking

            //First, clear flags
            performCorpusUpdate = false;
            isFirstPass = true; //initialization modules will need to be rerun

            doRestartingState(reason);
        }
        else if(IDLE == myState)
        {
            doIdleState(reason);
        }
        else if(WAITING_FOR_TASKING == myState)
        {
            //Clear flags
            performCorpusUpdate = false;
            isFirstPass = true;

            doTaskingState(reason);
        }
        else if(FAILED == myState)
        {
            //Don't do anything.
            //A command to STOP or SHUTDOWN exits this state
            LOG_INFO << "FAILED.  Waiting on server commanding...";
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //1 second sleep
        }
        else if(PAUSED == myState)
        {
            //Don't do anything.
            //A command to RESTART, STOP or SHUTDOWN exits this state
            LOG_DEBUG << "PAUSED.  Waiting on server commanding...";
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //1 second sleep
        }
        else
        {
            //This should never be possible
            LOG_ERROR << "Invalid VmfApplication State:" << myState;
            throw RuntimeException("Invalid VmfApplicationState", RuntimeException::OTHER);
        }

        //-----------Now handle any incoming commands---------------
        if(!shutdownSignalReceived) //If we are about to shutdown, don't check for commands
        {
            handleCommands(reason,performCorpusUpdate);
        }
 
    } //end while loop

    //----------Fuzzing loop exited, inform server of imminent shutdown-----------
    LOG_INFO << "Unregistering with server";
    if(reason.length()==0)
    {
        CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::UNREGISTER, "User manually shutdown");
    }
    else
    {
        CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::UNREGISTER, reason);
    }

}

/**
 * @brief Helper method to run the fuzzer in distributed fuzzing mode
 * This calls upon the controller to fuzz and handle controller commands.
 * If something goes wrong, we will transition to the FAILED state.
 * If it completes fuzzing, we will transition to the IDLE state.
 * 
 * @param reason state transition reason used for communicating back to the server
 * @param performCorpusUpdate when true, a corpus update should be performed
 * @param isFirstPass true on the first pass of through RUNNING with this tasking, false otherwise
 */
void VmfApplication::doRunningState(std::string& reason, bool performCorpusUpdate, bool isFirstPass)
{
    if(nullptr == myController)
    {
        LOG_ERROR << "Attempted to run VMF without a controller module";
        myState = FAILED;
        reason = "No controller module was specified";
        CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::FAILED, reason);
    }
    else
    {
        //Corpus Update can only happen in the running state
        if(performCorpusUpdate)
        {
            myController->handleCommand(*myStorage,distributedMode,ControllerModule::NEW_CORPUS);
        }
        else
        {
            //Command handling gets a chance to run on every pass, in case there is leftover work
            //that the top-level controller needs to perform
            myController->handleCommand(*myStorage,distributedMode,ControllerModule::NONE);
        }


        bool complete = false;
        try
        {
            complete = myController->run(*myStorage, isFirstPass);
        }
        catch(RuntimeException e)
        {
            reason = e.getReason();
            LOG_ERROR << "Controller encountered an exception -- " << reason;
            myState = FAILED;
            CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::FAILED, reason);
        }

        if(true == complete)
        {
            //Controller has requested completion of fuzzing
            myState = IDLE;
            myTaskingComplete = true; //The fuzzer finished doing what it was asked
            reason = "Fuzzing complete";
            LOG_INFO << "VMF Stopped due to " << reason << ".  Requesting new tasking from the server.";
            CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::IDLE, reason);
        }
    }
}

/**
 * @brief Helper method to perform RESTART for distributed fuzzing
 * This resets the fuzzer using the current tasking.  If anything
 * goes wrong, we transition to FAILED.  If all goes well, we transition
 * to RUNNING.
 * 
 * @param reason state transition reason used for communicating back to the server
 */
void VmfApplication::doRestartingState(std::string& reason)
{
    clearCurrentModules();

    try
    {
        loadAndInitModules();
    }
    catch(RuntimeException e)
    {
        reason = e.getReason();
        LOG_ERROR << "RESTART failed: " << reason;
        myState = FAILED;
        CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::FAILED, reason);
    }

    CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::RUNNING, "");
    myState = RUNNING;
}

/**
 * @brief Helper method to perform IDLE behaviors for distributed fuzzing.
 * This method re-registers with the server.  If this fails, there is not
 * much that VMF can do (because the server is dead), so the shutdownSignalReceived
 * flag is set.  If all goes well, we transition to WAITING_FOR_TASKING.
 * 
 * @param reason state transition reason used for communicating back to the server
 */
void VmfApplication::doIdleState(std::string& reason)
{
    //Clear the current fuzzing effort and transition to WAITING_FOR_TASKING
    bool valid = false;
    
    try
    {
        //Clear the current module data first
        clearCurrentModules();

        //Reset the config manager to the initial config files (server only)
        myConfig->reloadConfig();

        //Now repeat the initial registration
        valid = CDMSClient::getInstance()->sendRegistration(myTaskingComplete);
        if(!valid)
        {
            reason = "Unable to re-register with server";
        }

    }
    catch(RuntimeException e)
    {
        reason = e.getReason();
        LOG_ERROR << "Re-registration failed: " << reason;
        valid = false;
    }

    //If we were not able to reinitialize, this is a fatal error
    if(!valid)
    {
        shutdownSignalReceived = true;
    }
    else
    {
        myState = WAITING_FOR_TASKING;
        //We are about to get new tasking, so we reset the completion flag
        myTaskingComplete = false; 
    }
}

/**
 * @brief Helper method to perform WAIT_FOR_TASKING for distributed fuzzing.
 * This method polls the server for tasking.  If there is no tasking, it sleeps
 * to prevent us from re-polling too quickly.  If invalid tasking is received,
 * we transition to the FAILED state.  If valid tasking is received, we transition
 * to RUNNING.
 * 
 * @param reason state transition reason used for communicating back to the server
 */
void VmfApplication::doTaskingState(std::string& reason)
{
    CDMSClient* client = CDMSClient::getInstance();
    try
    {
        bool gotTasking = pollForTasking();
        if(!gotTasking)
        {
            //Sleep so that we are not polling too quickly
            LOG_INFO << "Waiting on CDMS tasking assignment...";
            std::this_thread::sleep_for(taskingSleepTime); //1 second sleep
            //TODO(VADER-943): Add timeout and retry registration?
        }
        else
        {
            //We have valid tasking
            client->sendRegistrationStatus(CDMSClient::RUNNING, "");
            myState = RUNNING;
        }
    }
    catch(RuntimeException e)
    {
        reason = e.getReason();
        LOG_ERROR << "Loading new tasking failed: " << reason;
        myState = FAILED;
        client->sendRegistrationStatus(CDMSClient::FAILED, reason);
    }
}

/**
 * @brief Helper method to perform command handling for distributed fuzzing
 * Based on the provided commands, myState, shutdownSignalReceived, performCorpusUpdate,
 * and reason will be modified.
 * 
 * @param reason reason for use in communicating back to the server
 * @param performCorpusUpdate when true, a corpus update should be performed
 */
void VmfApplication::handleCommands(std::string& reason, bool& performCorpusUpdate)
{
    std::vector<int> cmds = CDMSClient::getInstance()->getCommands();
    for(int serverCmd: cmds)
    {
        if(CDMSClient::NEW_CORPUS == serverCmd)
        {
            performCorpusUpdate = true;
        }
        else if(CDMSClient::RESTART == serverCmd)
        {
            if((PAUSED == myState))
            {
                myState = RESTARTING;
            }
            else
            {
                LOG_ERROR << "Cannot accept RESTART command -- not currently paused";
            }
        }
        else if(CDMSClient::SHUTDOWN == serverCmd)
        {
            shutdownSignalReceived = true;
            reason = "SHUTDOWN command received";
        }
        else if(CDMSClient::STOP == serverCmd)
        {
            myState = IDLE;
            reason = "STOP command received";
            LOG_INFO << "VMF Stopped because: " << reason << ".  Requesting new tasking from the server.";
            CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::IDLE, reason);
        }
        else if(CDMSClient::PAUSE == serverCmd)
        {
            myState = PAUSED;
            reason = "PAUSED command received";
            LOG_INFO << "VMF Paused because: " << reason << ".  Waiting for RESTART command from the server.";
            CDMSClient::getInstance()->sendRegistrationStatus(CDMSClient::PAUSED, reason);
        }
        else
        {
            LOG_ERROR << "Unknown server command: " << serverCmd;
        }
    }
  
}

/**
 * @brief Stop VMF
 * 
 * Stop signals the controller to stop executing.  It should be followed by a call
 * to shutdown to do individual module shutdown.
 * 
 * @throws RuntimeException if stop is called after a failed initialization
 */
void VmfApplication::stop()
{
    shutdownSignalReceived = true;
}
