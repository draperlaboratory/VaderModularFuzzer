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


#include "AFLFeedback.hpp"
#include "AFLExecutor.hpp"

namespace vader
{
/**
 * @brief Small helper struct used for tracking favorite testcases
 *
 */
typedef struct FavoredEntry {
    
    long id; ///< The StorageEntry id for the test case
    int executionTime; ///< The execution time associated with this test case
} FavoredEntry;

/**
 * @brief More complex version of AFLFeedback that includes favored test cases
 *
 */
class AFLFavoredFeedback : public AFLFeedback {
public:

    static Module* build(std::string name);
    virtual void init(ConfigInterface& config);

    virtual void registerStorageNeeds(StorageRegistry& registry);


    /**
     * @brief Construct a new AFLFavoredFeedback object
     * 
     * @param name the module name
     */
    AFLFavoredFeedback(std::string name);

    virtual ~AFLFavoredFeedback();
protected:
    virtual float computeFitness(StorageModule& storage, StorageEntry* e);
    int favoredTag; ///< handle for the tag "FAVORED"
private:
    bool updateFavoredTestcases(StorageModule& storage, StorageEntry* e);
    
    float favoredFitnessWeight;
    bool topRatedInitialized;
    FavoredEntry* top_rated;
};
}
