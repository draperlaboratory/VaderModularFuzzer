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
#include "AFLFavoredFeedback.hpp"
#include "Logging.hpp"
#include <set>

using namespace vmf;

#include "ModuleFactory.hpp"
REGISTER_MODULE(AFLFavoredFeedback);


/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* AFLFavoredFeedback::build(std::string name)
{
    return new AFLFavoredFeedback(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void AFLFavoredFeedback::init(ConfigInterface& config)
{
    AFLFeedback::init(config);

    favoredFitnessWeight = 5.0;
    if(useCustomWeights) //For consistency, only read these parameters when useCustomWeights is set
    {
      favoredFitnessWeight = config.getFloatParam(getModuleName(), "favoredWeight", 5.0);
    }

    if(favoredFitnessWeight > 1.0)
    {
      LOG_INFO << "Fitness weights: favored = " << favoredFitnessWeight;
    }
    else
    {
      LOG_WARNING << "Favored weight <= 1.0, this disables the favored computation";
    }

}

AFLFavoredFeedback::AFLFavoredFeedback(std::string name) :
    AFLFeedback(name)
{
    topRatedInitialized = false;
}

AFLFavoredFeedback::~AFLFavoredFeedback()
{
    if(topRatedInitialized)
        free(top_rated);
}

void AFLFavoredFeedback::registerStorageNeeds(StorageRegistry& registry)
{
    AFLFeedback::registerStorageNeeds(registry);
    traceBitsKey = registry.registerKey("AFL_TRACE_BITS", StorageRegistry::BUFFER_TEMP, StorageRegistry::READ_ONLY);
    
    favoredTag = registry.registerTag("FAVORED", StorageRegistry::READ_WRITE);
}

float AFLFavoredFeedback::computeFitness(StorageModule& storage, StorageEntry* e)
{
    bool isFavored = false;

    //Disable favored computation if the favored weight is <= 1.0
    if(favoredFitnessWeight > 1.0)
    {
      //Initialize the data top rated datastructure, if we haven't already done so
      if(!topRatedInitialized)
      {
          //Map size is not known until the executor writes this data
          int mapSize = e->getBufferSize(traceBitsKey);
          top_rated = (FavoredEntry *) malloc(sizeof(FavoredEntry) * mapSize);
          memset(top_rated, 0, sizeof(FavoredEntry) * mapSize);
          topRatedInitialized = true;
      }

      //Detect if this will be a favored testcase and mark it if so
      isFavored = updateFavoredTestcases(storage, e);
    }

    float fitness = AFLFeedback::computeFitness(storage,e);

    //Increase the fitness for favored test cases
    if (isFavored)
    {
      fitness *= favoredFitnessWeight;
    }

    return fitness;
}

/**
 * @brief Manages the top_rated list, a record of which testcase is the best (fastest) for each coverage byte.
 * Top rated testcases are "favored" and get a boost to their fitness.
 * 
 * @return true if the current test case is favored
 */
bool AFLFavoredFeedback::updateFavoredTestcases(StorageModule& storage, StorageEntry* e)
{
  bool isFavored = false;
  char* coverage = e->getBufferPointer(traceBitsKey);
  int coverageSize = e->getBufferSize(traceBitsKey);
  int executionTime = getExecTimeMs(e);
  long id = e -> getID();
  std::set<long> unfavoredTestcases = std::set<long>();

  // If this entry hits new coverage bytes or is faster than the existing best, mark it is a favorite
  for (int i = 0; i < coverageSize; i++)
  {
    if (coverage[i] != 0)
    {
      // If there is no entry yet for this byte, or if this case is faster, then install as favorite
      if (top_rated[i].id == 0 || executionTime < top_rated[i].executionTime)
      {
        // If we kicked out another entry, track that for later maintenance
        if (top_rated[i].id != 0)
          unfavoredTestcases.insert(top_rated[i].id);

        top_rated[i].id =  id;
        top_rated[i].executionTime = executionTime;
        e->addTag(favoredTag);
        isFavored = true;
      }
    }
  }

  // Make a pass over all IDs that got removed. If they are no longer a favorite for any byte, then we unfavorite them.
  // If they got removed from a byte but are still a favorite for another byte somewhere, do *not* unfavorite them.
  for (long removedID : unfavoredTestcases)
  {
    // Determine if we should unfavorite this testcase: are there other bytes still claimed by it?
    bool unfavorite = true;
    for (int i = 0; i < coverageSize; i++)
    {
      if (top_rated[i].id == removedID)
      {
        unfavorite = false;
        break;
      }
    }

    // If so, try to lookup that StorageEntry to untag it and update fitness to indicate not favorited.
    // Messy: we can't execute again from here to evaluate new fitness because state is all for current testcase
    // So instead, divide by 5 to remove the benefit of being favorited.
    if (unfavorite)
    {
      //LOG_INFO << "Testcase " << removedID << " has been removed as a favorite.";
      StorageEntry * removedEntry = storage.getSavedEntryByID(removedID);
      if (removedEntry != nullptr)
      {
        removedEntry->removeTag(favoredTag);
        // Reduce fitness
        float fitness = removedEntry -> getFloatValue(fitnessKey);
	      float newFitness = fitness / favoredFitnessWeight;
        removedEntry->setValue(fitnessKey, newFitness);
      }
    }
  }
   
  return isFavored;
}
