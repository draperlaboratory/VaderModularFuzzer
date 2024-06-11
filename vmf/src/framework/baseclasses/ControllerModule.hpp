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

#include "StorageUserModule.hpp"
#include <chrono>

namespace vmf
{
/**
 * @brief Base class for VMF Controller Modules
 *
 * Controller modules are the top level module in Vader.  The controller module is required to manage 
 * the sequencing of the “fuzzing loop”, and call StorageModule::clearNewAndLocalEntries() at the end 
 * of each fuzzing loop.
 * 
 * Controllers should be written to be fairly generic to the set of modules being used.  
 * Controllers should not be adding/modifying/deleting test cases in storage.
 * 
 * Controllers typically support submodules of type:  InitializationModule, ExecutorModule, 
 * FeedbackModule, InputGeneratorModule, and OutputModule.  Controllers with Executor and 
 * Feedback submodules are responsible for determining which storage entries are used by these 
 * modules.  However, a Controller could be written to manager other controllers, in which case 
 * its submodules would also be of type Controller.
 */
class ControllerModule : public StorageUserModule {
public:
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void registerMetadataNeeds(StorageRegistry& registry) {};

    /**
     * @brief Run the controller
     *
     * This method runs the controller.  It will be called over and
     * over to execute one pass through the fuzzing loop.  Controllers
     * may optionally indicate that fuzzing is complete, or they may
     * continue until interupted by an external factor.
     * 
     * @param storage a reference to the storage module
     * @param isFirstPass true if this the first time run is being called, false otherwise
     * 
     * @return true to indicate that fuzzing is complete, false otherwise
     */
    virtual bool run(StorageModule& storage, bool isFirstPass) = 0;

    /**
     * @brief Command types that can be provided to the Controller command handler
     * This is primarily for distributed fuzzing support.
     * NEW_CORPUS indicates that new server based corpus information is available, if
     * the controller would like to incorperate it
     */
    enum ControllerCmdType
    {
        NEW_CORPUS
    };

    /**
     * @brief Handle any controller commands
     * 
     * This method may be overwritten by a subclass, but care must be taken to properly
     * support distributed fuzzing functions.
     * 
     * @param storage a reference to the storage module
     * @param isDistributed true if the controller is being run in distributed mode
     * @param cmd the command to handle
     */
    virtual void handleCommand(StorageModule& storage, bool isDistributed, ControllerCmdType cmd);

    virtual ~ControllerModule() {};

  /**
     * @brief Helper method to return a single Controller submodule from config
     * This method will retrieve a single Controller submodules for the specified parent modules.
     * If there are no Controller submodules, then an nullptr will be returned.  If there are more
     * than one Controller submodules specified, than an exception will be thrown.  Use the list form
     * of this method getControllerSubmodules(), if more than one Controller module can be specified.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return ControllerModule* the submodule, or nullptr if none is specified
     */
    static ControllerModule* getControllerSubmodule(ConfigInterface& config, std::string parentName);

    /**
     * @brief Helper method to return a single Controller submodule from config by name
     * This method will retrieve a single Controller submodule by name for the specified parent modules.
     * If there are no Controller submodules with the specified name, then an nullptr will be returned.  
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @param childName the name of the child module to finde
     * @return ControllerModule* the submodule, or nullptr if none is found
     */
    static ControllerModule* getControllerSubmoduleByName(ConfigInterface& config, std::string parentName, std::string childName);
    
    /**
     * @brief Helper method to get the Controller Submodules from config
     * This method will retrieve all of the Controller submodules for the specified parent modules.
     * If there are no Controller submodules, then an empty list will be returned.
     * 
     * @param config the ConfigInterface object
     * @param parentName the name of the parent module
     * @return std::vector<ControllerModule*> the list of submodules
     */
    static std::vector<ControllerModule*> getControllerSubmodules(ConfigInterface& config, std::string parentName);

    /**
     * @brief Convenience method to determine if a module is actually a controller
     * 
     * @param module 
     * @return true if this module has a module type=CONTROLLER
     * @return false 
     */
    static bool isAnInstance(Module* module);

    /**
     * @brief Convenience method to cast Module* to ControllerModule*
     * 
     * Call isAnInstance first to check the type in order to avoid an exception.
     * 
     * @param module 
     * @return ControllerModule* 
     * @throws RuntimeException if the underlying Module* is not a decendant of ControllerModule
     */
    static ControllerModule* castTo(Module* module);
    
protected:
    /**
     * @brief Construct a new Controller Module object
     * 
     * @param name the module name
     */
    ControllerModule(std::string name);

    /// The list of tags that the controller is interested in (for distributed fuzzing)
    std::string tags;

    /// The server test case tag handle, used to tag test cases that are incoming from the server (for distributed fuzzing)
    int serverTestCaseTag;

    /// The test case handle, use to write test cases (for distributed fuzzing)
    int testCaseKey;

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