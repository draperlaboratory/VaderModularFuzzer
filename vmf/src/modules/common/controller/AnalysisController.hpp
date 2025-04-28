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

#include "ControllerModulePattern.hpp"

namespace vmf
{
/**
 * @brief Analysis-Oriented controller that executes test cases and then feeds them into output modules
 *
 * This controller is designed for analysis-oriented tasks, where a bunch of test cases need
 * to be run and then the results need to be analysed by one or more output modules.
 * 
 * This controller requires at least one Executor and Feedback module.  It supports any number of
 * input generation, initialization, and output modules.  Typically users of this module will want to
 * use at least one output module, but it is not required to do so.
 * 
 * The execution pattern is to run the initialization modules once, followed by the input generation modules.
 * Then the executor and feedback modules are executed, followed by the output modules.  When running in standalone
 * mode, this will occur in a single pass through the fuzzing loop. When using this controller for distributed 
 * fuzzing, it may take more than one pass through the fuzzing loop to run everything once (because server test 
 * cases are loaded in batches).  In this case, the output modules will only be run once in the final pass through 
 * the fuzzing loop.
 * 
 * Note: Scheduling preferences of output modules are ignored with this controller --
 * all output modules run only once at the end of the fuzzer.
 */
class AnalysisController : public ControllerModulePattern {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual bool run(StorageModule& storage, bool isFirstPass);

    AnalysisController(std::string name);
    virtual ~AnalysisController();

private:
    ///Because output modules are not scheduled, this controller does not use the OutputScheduler class
    std::vector<OutputModule*> outputs;

};
}