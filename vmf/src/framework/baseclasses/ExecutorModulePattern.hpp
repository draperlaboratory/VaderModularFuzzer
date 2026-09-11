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

#include "ExecutorModule.hpp"
#include "StorageModule.hpp"

namespace vmf {

/**
* @brief Helper class for implementing executors.  
* This class cannot be used as an executor on its own, as it does
* not implement the runTestCase method.  Rather, it provides helper
* methods that can be used as the basis of implementing an executor.
*/
class ExecutorModulePattern : public ExecutorModule {
public:

    /**
     * @brief Calls a generic configuration loader
     */
    virtual void init(ConfigInterface& config);

    /**
     * @brief Separates runTestCase into three stages, preDisptach,
     * dispatchTestCase, and postDispatch.
     *
     * This decomposition isolates runTestCase behavior specific to
     * each stage of running a testcase.
     *
     * 1. preDispatch: Prep executor and SUT state prior to dispatching a
     * testcase
     * 2. dispatchTestCase: Deliver testcase to the SUT and wait for completion
     * 3. postDispatch: Consume collected runtime data with updates to storage
     */
    virtual void runTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Implements calibration measurements and timeout calculation reusing runTestCase
     */
    virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator);

    /**
     * @brief Registers access for test case, exec time,
     *  crashed/hung/incomplete/normal tags, maxCalibrationCases
     */
    virtual void registerStorageNeeds(StorageRegistry& registry);

    /**
     * @brief Purely virtual
     */
    virtual void registerMetadataNeeds(StorageRegistry& registry);

protected:

    /**
     * @brief Ensures timeouts are set, clear trace coverge map. Calls setTimeouts
     * 
     * @param storage 
     * @return entry the entry to execute
     */
    virtual void preDispatch(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Purely virtual
     * 
     * @param storage 
     * @return entry the entry to execute
     */
    virtual void dispatchTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Writes execution time to storage, evaluate SUT
     * execution. Calls evalExecStatus
     * 
     * @param storage 
     * @return entry the entry to execute
     */
    virtual void postDispatch(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Set internal timeouts to bound execution
     * 
     * @param timeout Timeout in miliseconds
     */
    void setTimeouts(int timeout);

    /**
     * @brief Capture generic configurations such as sutArgv, ignoreHangs,
     * capturing stdout/stderr, timeouts, custom exit code as crash
     * 
     * @param config
     */
    void loadConfig(ConfigInterface &config);
    
private:

    /// Default Timeout in milliseconds
    static const int DEFAULT_TIMEOUT_MS = 100;
    int configured_timeout = DEFAULT_TIMEOUT_MS;
    int current_timeout;
    int sut_exec_status;

    /* Storage keys and tags */
    ///TEST_CASE handle
    int test_case_key;
    ///EXEC_TIME_US handle
    int exec_time_key;
    ///CRASHED tag
    int crashed_tag;
    ///HUNG tag
    int hung_tag;
    ///INCOMPLETE tag for liveness-only fuzzing
    int incomplete_tag;
    ///RAN_SUCCESSFULLY tag
    int normal_tag;
