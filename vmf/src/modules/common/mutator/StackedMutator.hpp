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

#include "MutatorModule.hpp"
#include "StorageEntry.hpp"
#include "MutatorSelector.hpp"
#include "ConfigInterface.hpp"
#include "VmfRand.hpp"

#include <map>

using namespace vmf;

/**
 * @brief Stacked Mutation Module
 * 
 * Takes a list of mutators and composes them into a single atomic mutation operation
 * 
 * Able to support randomization along stack size, mutator selection, selection distribution, and application limitation
 * 
 */
class StackedMutator : public MutatorModule
{
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    
    StackedMutator(std::string name);
    virtual ~StackedMutator();
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void mutateTestCase(StorageModule &storage, StorageEntry *baseEntry, StorageEntry *newEntry, int testCaseKey);

    /**
     * @brief Get the mutation stack used to mutate the last test case
     */
    std::vector<MutatorModule*> getStack(void);
private:
    // helper functions
    std::vector<MutatorModule*> generateMutatorStack(void);
    StorageEntry* applyStack(std::vector<MutatorModule*> stack, std::vector<StorageEntry*> &temps, vmf::StorageModule &storage, int testCaseKey);
    std::string getStackAsString(std::vector<MutatorModule*>);
    void mutateLayers(vmf::StorageModule &storage, std::vector<vmf::StorageEntry *> &temps, int testCaseKey);
    void mutateLayer(vmf::StorageModule &storage, vmf::MutatorModule *m, std::vector<vmf::StorageEntry *> &temps, int testCaseKey);
    void initMutatorSelector(
        ConfigInterface& config,
        std::vector<MutatorModule*> mutators);


    // Stack configuration fields
    int _StackedMutator_max_size, _StackedMutator_num_mutators;
    bool _StackedMutator_randomize_stack_size;
    std::vector<MutatorModule*> _StackedMutator_mutators;  // the pool of mutators available
    std::vector<MutatorModule*> _StackedMutator_stack;     // the stack used to perform the last mutation
    MutatorSelector* _StackedMutator_selection_algorithm;
    std::string _StackedMutator_user_choice;
    
    // Stack utility fields
    VmfRand* random;
};


