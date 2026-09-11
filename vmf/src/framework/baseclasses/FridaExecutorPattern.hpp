/* =============================================================================
 * Vader Modular Fuzzer (VMF) Copyright (c) 2021-2025 The Charles
 * Stark Draper Laboratory, Inc.  <vmf@draper.com>
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
* @brief Helper class for implementing executors operating with Frida
* dynamic binary instrumentation. This class cannot be used as an
* executor on its own, as it does not implement the runTestCase
* method.  Rather, it provides helper methods that can be used as the
* basis of implementing an executor.
* 
* This pattern supports interacting with uninstrumneted binaries on
* Windows.
*/

class FridaExecutorPattern : public ExecutorModule {
public:

    /**
     * @brief loads configuration, launches forkserver, probes
     * forkserver for runtime data configuration
     */
    virtual void init(ConfigInterface& config);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void runTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void runCalibrationCases(StorageModule& storage, std::unique_ptr<Iterator>& iterator);

    /**
     * @brief Inherited from ExecutorModulePattern
     */
    virtual void registerStorageNeeds(StorageRegistry& registry);

    /**
     * @brief Inherited from ExecutorModulePattern 
     */
    virtual void registerMetadataNeeds(StorageRegistry& registry);

protected:
    
    /**
     * @brief Verifies timeouts are set and resets single-run timer
     * 
     * @param storage 
     * @return entry the entry to execute
     */
    virtual void preDispatch(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Delivers the testcase to the forkserver, launches it,
     * bounds execution, and captures execution status
     * 
     * @param storage 
     * @param entry the entry to execute
     */
    virtual void dispatchTestCase(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Updates storage with data from executing the current testcase
     * 
     * @param storage 
     * @param entry the entry to execute
     */

private:

    /**
     * @brief Configures internal options using configuration opertions
     * passed to this ExecutorModule from Module
     *
     * Configuration options include:
     * - Output directory
     * - Optional Manual Timeout (microseconds)
     * - Timeout Calibration thresholds/constants
     * - Debug logging
     */
    void loadConfig(ConfigInterface &config);
  
    /**
     * @brief Launch forkserver SUT process
     */
    bool startSUT();

    /**
     * @brief Kills fokserver process group and releases
     * shared memory segments.
     */
    void releaseResources(void);

    /**
     * @brief Initializes pipes and resource limits for SUT
     */
    bool initSUTControl(void);

    /**
     * @brief Initializes the shared memory regions for runtime and test 
     * data
     */
    bool initSharedMemory(void);
  
    /**
     * @brief wait for Results or crash and ensure sut is ready for next
     */
    void waitForResultsThenReady(uint32_t size);

    /**
     * @brief Identify SUT run status
     */
    void handleStatus(StorageModule& storage, StorageEntry* entry);

    /**
     * @brief Checks error value received from waitpid/forkserver to
     * determine if the SUT crashed
     *
     * @param status Status to be checked
     * @return bool Whether or not the status value corresponds to a crash
     */
    bool isCrash(int status);
}
