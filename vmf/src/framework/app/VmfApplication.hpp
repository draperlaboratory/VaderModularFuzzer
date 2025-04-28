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
#include "ModuleManager.hpp"
#include "StorageModule.hpp"
#include "ConfigManager.hpp"
#include "Plugins.hpp"
#include "ControllerModule.hpp"
#include <string>
#include <chrono>

namespace vmf
{
/**
 * @brief Called by main() to create, run and shutdown VMF.
 */
class VmfApplication
{
public:

    #define VERSION_NUMBER "5.0.0"

    VmfApplication();
    ~VmfApplication();

    bool init(int argc, char** argv);
    void run();
    void stop();

private:

    enum AppState
    {
        RUNNING,
        WAITING_FOR_TASKING,
        RESTARTING,
        IDLE,
        PAUSED,
        FAILED
    };

    void runDistributed();
    void runStandalone();

    void loadPlugins();
    bool parseConfigParams(int argc, char** argv);
    void printUsage();
    bool localInit();

    //Server initialization helper methods
    bool        serverInit();
    bool        pollForTasking();

    //Server reinitialization helper methods
    void        clearCurrentModules();

    //Distributed fuzzing helper methods
    void handleCommands(std::string& reason, bool& performCorpusUpdate);
    void doRunningState(std::string& reason, bool performCorpusUpdate, bool isFirstPass);
    void doRestartingState(std::string& reason);
    void doIdleState(std::string& reason);
    void doTaskingState(std::string& reason);

    //General intialization helper method
    std::string createOutputDir();
    void        loadAndInitModules();
    
    ModuleManager            myModuleManager;
    StorageModule*           myStorage              = nullptr;
    PluginLoader             myPluginLoader;
    StorageRegistry*         myRegistry             = nullptr;
    StorageRegistry*         myMetadataRegistry     = nullptr;
    ConfigManager*           myConfig               = nullptr;
    ControllerModule*        myController           = nullptr;
    std::vector<std::string> configFiles;
    bool                     distributedMode        = false;
    bool                     shutdownSignalReceived = false;

    /// @brief This is used to track the state of this VMF fuzzer
    AppState                 myState                = FAILED;
    /// @brief This flag is used to track whether the controller is the one requesting completion of fuzzing
    bool                     myTaskingComplete      = false;

    std::chrono::milliseconds taskingSleepTime;
};
}
