/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2023 Vigilant Cyber Systems
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

#include "GramatronPDA.hpp"
#include "GramatronHelpers.hpp"
#include "Module.hpp"
#include "InitializationModule.hpp"
#include <string>
#include "ModuleFactory.hpp"

namespace vmf
{
/**
 * @brief Seed generator that will create an initial set of test cases from a Pushdown Automata Representation of a Context Free Grammar
 *
 *
 */
class GramatronBasedSeedGen: public InitializationModule {
public:
    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);
    virtual void registerStorageNeeds(StorageRegistry& registry);
    virtual void run(StorageModule& storage);

    GramatronBasedSeedGen(std::string name);
    virtual ~GramatronBasedSeedGen();
private:
    int testCaseKey;
    int autRepKey;
    int numTestCases;
    PDA* pda;
};
}

