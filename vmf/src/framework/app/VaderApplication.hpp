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
#pragma once
#include "ModuleFactory.hpp"
#include "StorageModule.hpp"
#include "ConfigManager.hpp"
#include "Plugins.hpp"
#include "ControllerModule.hpp"
#include <string>
#include <chrono>

namespace vader
{
/**
 * @brief Called by main() to create, run and shutdown VMF.
 */
class VaderApplication
{
public:

    #define VERSION_NUMBER "3.2.0"

    VaderApplication();
    ~VaderApplication();

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
