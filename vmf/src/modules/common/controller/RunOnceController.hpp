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

#include "ControllerModulePattern.hpp"

namespace vmf
{
/**
 * @brief Controller runs every provided module exactly once before shutting down
 * This Controller supports any number of modules.  All module types are optional, however
 * a feedback module cannot be specified without an executor to go with it, and if
 * an executor module is used a feedback modules must be provided as well.
 * Note: Scheduling preferences of output modules are ignored with this controller --
 * all output modules run once at the end of the one loop through the fuzzer.
 */
class RunOnceController : public ControllerModulePattern {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    //This controller has no additional storage needs
    //virtual void registerStorageNeeds(StorageRegistry& registry);
    //virtual void registerMetadataNeeds(StorageRegistry& registry);

    virtual bool run(StorageModule& storage, bool isFirstPass);

    RunOnceController(std::string name);
    virtual ~RunOnceController();

private:
    ///Because output modules are not scheduled, this controller does not use the OutputScheduler class
    std::vector<OutputModule*> outputs;

};
}