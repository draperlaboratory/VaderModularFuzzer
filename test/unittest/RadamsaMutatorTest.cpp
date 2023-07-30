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

#include "gtest/gtest.h"
#include "RadamsaMutator.hpp"
#include "SimpleStorage.hpp"

using namespace vader;

class RadamsaMutatorTest : public ::testing::Test {
 protected:
  StorageModule* storage;
  StorageRegistry* registry;
  StorageRegistry* metadata;
  RadamsaMutator* theMutator;
  int testCaseKey;

  RadamsaMutatorTest() {
    storage = new SimpleStorage("storage");
    registry = new StorageRegistry();
    metadata = new StorageRegistry();
    theMutator = new RadamsaMutator("rTestMutator");
  }

  ~RadamsaMutatorTest() override {}

  void SetUp() override {
    theMutator->registerStorageNeeds(*registry);
    theMutator->registerMetadataNeeds(*metadata);
    testCaseKey = registry->registerKey("TEST_CASE", StorageRegistry::BUFFER,
                                        StorageRegistry::READ_WRITE);

    // registry->validateRegistration();
    storage->configure(registry, metadata);
  }

  void TearDown() override 
  {
    delete theMutator;
    delete registry;
    delete metadata;
    delete storage;
  }

  bool areBuffersDifferent(StorageEntry* baseEntry, StorageEntry* modEntry, int key)
  {
    bool areDiff = false;
    int sz1 = baseEntry->getBufferSize(key);
    int sz2 = modEntry->getBufferSize(key);
    if(sz1 != sz2) /* size is different */
    {
      areDiff = true;
    }
    else /* size is same, check contents */
    {
      char* buff1 = baseEntry->getBufferPointer(key);
      char* buff2 = modEntry->getBufferPointer(key);
      for (int idx = 0; idx < sz1; idx++) 
      {
        // std::cout << buff1[idx] << ", " << buff2[idx] << "\n" << std::flush;
        if (buff1[idx] != buff2[idx]) 
        {
          areDiff = true;
          break;
        }
      }
    }
    return areDiff;
  }

};  // class RadamsaMutatorTest

TEST_F(RadamsaMutatorTest, TestAlgorithm) {
  // create a base entry for algorithms to modify
  StorageEntry* baseEntry = storage->createNewEntry();
  char* buff = baseEntry->allocateBuffer(testCaseKey, 4);
  buff[0] = 'T';
  buff[1] = 'E';
  buff[2] = 'S';
  buff[3] = 'T';

  std::cout << "Testing Radamsa \n";
  StorageEntry* modEntry = nullptr;
  try 
  {
    modEntry = theMutator->createTestCase(*storage, baseEntry);
  } 
  catch (BaseException e) 
  {
    FAIL() << "Exception thrown: " << e.getReason() << "\n";
  }

  EXPECT_TRUE(nullptr != modEntry)
      << "Radamsa createTestCase returned null pointer \n";
  EXPECT_TRUE(areBuffersDifferent(baseEntry, modEntry, testCaseKey))
      << "Radamsa output not different than input \n";
}
