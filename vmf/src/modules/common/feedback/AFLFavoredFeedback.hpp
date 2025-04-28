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


#include "AFLFeedback.hpp"

namespace vmf
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
 * AFLFavoredFeedback requires as an input the AFL_TRACE_BITS buffer.
 * It outputs a FITNESS value in storage that includes a fitness boost for
 * favored test cases (where a test case is "favored" if it was the fastest
 * test case that covered a particular coverage byte).
 * @image html CoreModuleDataModel_2.png width=800px
 * @image latex CoreModuleDataModel_2.png width=6in
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
    int traceBitsKey; ///<handle for the "AFL_TRACE_BITS" field
private:
    bool updateFavoredTestcases(StorageModule& storage, StorageEntry* e);
    
    float favoredFitnessWeight;
    bool topRatedInitialized;
    FavoredEntry* top_rated;
};
}
