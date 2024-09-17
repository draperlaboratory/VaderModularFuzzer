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
#include "gtest/gtest.h"
#include "AFLCloneMutator.hpp"
#include "AFLDeleteMutator.hpp"
#include "AFLFlip2BitMutator.hpp"
#include "AFLFlip2ByteMutator.hpp"
#include "AFLFlip4BitMutator.hpp"
#include "AFLFlip4ByteMutator.hpp"
#include "AFLFlipBitMutator.hpp"
#include "AFLFlipByteMutator.hpp"
#include "AFLRandomByteAddSubMutator.hpp"
#include "AFLRandomByteMutator.hpp"
#include "AFLSpliceMutator.hpp"
#include "SimpleStorage.hpp"
#include "ModuleTestHelper.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class AFLMutatorTest : public ::testing::Test {
  protected:


  AFLMutatorTest()
  {
    storage = new SimpleStorage("storage");
    registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);
    metadata = new StorageRegistry();
    testHelper = new ModuleTestHelper();
    config = testHelper -> getConfig();
  }

  ~AFLMutatorTest() override {

  }


  void SetUp() override {

        testCaseKey = registry->registerKey(
            "TEST_CASE", 
            StorageRegistry::BUFFER, 
            StorageRegistry::READ_WRITE
        );
        int_key = registry->registerKey(
            "TEST_INT",
            StorageRegistry::INT,
            StorageRegistry::READ_WRITE
        );
        normalTag = registry->registerTag(
            "RAN_SUCCESSFULLY",
            StorageRegistry::WRITE_ONLY
        );
        // registry->validateRegistration();
        storage->configure(registry, metadata);
  }

  void TearDown() override {
      delete registry;
      delete metadata;
      delete storage;
  }

  StorageModule* storage;
  StorageRegistry* registry;
  StorageRegistry* metadata;
  ModuleTestHelper* testHelper;
  TestConfigInterface* config;

  int testCaseKey;
  int int_key;
  int normalTag;

  bool areBuffersDifferent(char* buff1, char* buff2, int size) 
  {
    bool areDiff = false;
    for (int idx = 0; idx < size; idx++) 
    {
      // std::cout << buff1[idx] << ", " << buff2[idx] << "\n" << std::flush;
      if (buff1[idx] != buff2[idx]) {
        areDiff = true;
        break;
      }
    }
    return areDiff;
  }

  //test algorithms that are intended to change buffer contents but preserve buffer length
  void testAlgBuffEqLength(MutatorModule& mutator, StorageEntry* baseEntry)
  {
    std::string name = mutator.getModuleName();
    GTEST_COUT << "Testing " << name << "\n";
    mutator.registerStorageNeeds(*registry);
    mutator.registerMetadataNeeds(*metadata);

    StorageEntry* modEntry = storage->createNewEntry();
    try{
        mutator.mutateTestCase(*storage, baseEntry, modEntry, testCaseKey);
    } 
    catch (BaseException e)
    {
      FAIL() << "Exception thrown: " << e.getReason();
    }
    EXPECT_EQ(baseEntry->getBufferSize(testCaseKey), modEntry->getBufferSize(testCaseKey)) << name << " buffer size not equal";
    EXPECT_TRUE(areBuffersDifferent(baseEntry->getBufferPointer(testCaseKey), 
                                        modEntry->getBufferPointer(testCaseKey), 
                                        baseEntry->getBufferSize(testCaseKey))) << name << " buffers are not different.";
  }

  void testSplice(int baseSize, int secondSize)
  { 
    AFLSpliceMutator theMutator("AFLSpliceMutator");
    theMutator.init(*config);
    theMutator.registerStorageNeeds(*registry);
    theMutator.registerMetadataNeeds(*metadata);

    // create first test case that will be used in splice
    // will contain all 1's
    int baseVal = 1;
    StorageEntry* baseEntry; 
    char* baseBuf;
    baseEntry = storage->createNewEntry();
    baseEntry->setValue(int_key, 0);
    baseBuf = baseEntry->allocateBuffer(testCaseKey, baseSize);
    for(int j=0; j<baseSize; j++)
    {   baseBuf[j] = baseVal; }
    storage->saveEntry(baseEntry);
    baseEntry->addTag(normalTag);

    // create additional test cases, one random one will be chosen for splicing
    // each test case is entirely populated single value, which is different for each case
    // and cannot be 1 which is used for the base case
    StorageEntry* entry; 
    char* buf;
    for (int i = 2; i <= 6; i++)
    {
        entry = storage->createNewEntry();
        entry->setValue(int_key, i);
        buf = entry->allocateBuffer(testCaseKey, secondSize);
        for(int j=0; j<secondSize; j++)
        {   buf[j] = i; }
        storage->saveEntry(entry);
        entry->addTag(normalTag);
    }
    storage->clearNewAndLocalEntries();

    // create a new test case by splicing 2 test cases
    StorageEntry* modEntry = storage->createNewEntry();
    try
    {
        theMutator.mutateTestCase(*storage, baseEntry, modEntry, testCaseKey);
    } 
    catch (BaseException e)
    {
        FAIL() << "Exception thrown: " << e.getReason();
    }

    char* newBuf = modEntry->getBufferPointer(testCaseKey);
    int newBufSize = modEntry->getBufferSize(testCaseKey);

    // test size of new buffer
    ASSERT_EQ(secondSize, newBufSize) << "Spliced case is not of expected size";
    
    // first index should be the same as baseCase (baseCase should not be entirely overwritten)
    EXPECT_EQ(baseVal, newBuf[0]) << "First index of baseCase has been overwritten";
    
    // test that everything after the splice point comes from the second testcase in the splice
    bool foundSplice = false;
    int splicedVal = -1;
    for(int p = 0; p < newBufSize; p++)
    {
        if(false == foundSplice)
        {
            if(baseVal != newBuf[p])
            {
                foundSplice = true;
                splicedVal = newBuf[p];
            }
        }
        else
        {
            EXPECT_EQ(splicedVal, newBuf[p]) << "Values after splice point not all the same (i.e. from second test case)";
        }
    }
    if(newBufSize > 1)
    {
      EXPECT_TRUE(foundSplice) << "Spliced test case does not appear to contain values from 2 different test cases";
    }
    //If the resulting buffer is only 1 character long, then there is no second byte
  }

}; // class AFLMutatorTest



TEST_F(AFLMutatorTest, TestAlgorithms) 
{ 
  //create a base entry for algorithms to modify
  StorageEntry* baseEntry = storage->createNewEntry();
  char* buff = baseEntry->allocateBuffer(testCaseKey, 12);
  buff[0] = 'T';
  buff[1] = 'E';
  buff[2] = 'S';
  buff[3] = 'T';
  buff[4] = '1';
  buff[5] = '2';
  buff[6] = '3';
  buff[7] = '4';
  buff[8] = '5';
  buff[9] = '6';
  buff[10] = '7';
  buff[11] = '8';

  AFLFlipBitMutator flipBit("AFLFlipBitMutator");
  flipBit.init(*config);
  testAlgBuffEqLength(flipBit, baseEntry);

  AFLFlip2BitMutator flip2Bit("AFLFlip2BitMutator");
  flip2Bit.init(*config);
  testAlgBuffEqLength(flip2Bit, baseEntry);

  AFLFlip4BitMutator flip4Bit("AFLFlip4BitMutator");
  flip4Bit.init(*config);
  testAlgBuffEqLength(flip4Bit, baseEntry);

  AFLFlipByteMutator flipByte("AFLFlipByteMutator");
  flipByte.init(*config);
  testAlgBuffEqLength(flipByte, baseEntry);

  AFLFlip2ByteMutator flip2Byte("AFLFlip2ByteMutator");
  flip2Byte.init(*config);
  testAlgBuffEqLength(flip2Byte, baseEntry);

  AFLFlip4ByteMutator flip4Byte("AFLFlip4ByteMutator");
  flip4Byte.init(*config);
  testAlgBuffEqLength(flip4Byte, baseEntry);

  AFLRandomByteAddSubMutator randomAddSub("AFLRandomByteAddSubMutator");
  randomAddSub.init(*config);
  testAlgBuffEqLength(randomAddSub, baseEntry);

  AFLRandomByteMutator random("AFLRandomByteMutator");
  random.init(*config);
  testAlgBuffEqLength(random, baseEntry);

  AFLDeleteMutator deleteMutator("AFLDeleteMutator");
  deleteMutator.init(*config);
  deleteMutator.registerStorageNeeds(*registry);
  deleteMutator.registerMetadataNeeds(*metadata);

  StorageEntry* modEntry = storage->createNewEntry();
  deleteMutator.mutateTestCase(*storage, baseEntry, modEntry, testCaseKey);
  EXPECT_NE(baseEntry->getBufferSize(testCaseKey), modEntry->getBufferSize(testCaseKey)) << "DELETE BYTES did not change buffer size";

  AFLCloneMutator cloneMutator("AFLCloneMutator");
  cloneMutator.init(*config);
  cloneMutator.registerStorageNeeds(*registry);
  cloneMutator.registerMetadataNeeds(*metadata);

  StorageEntry* modEntry2 = storage->createNewEntry();
  cloneMutator.mutateTestCase(*storage, baseEntry, modEntry2, testCaseKey);
  EXPECT_NE(baseEntry->getBufferSize(testCaseKey), modEntry2->getBufferSize(testCaseKey)) << "CLONE BYTES did not change buffer size";;
}

// 2 tests to have tear down clean up in between
TEST_F(AFLMutatorTest, TestSpliceAlgorithm) 
{ 
    testSplice(2, 5);
}
TEST_F(AFLMutatorTest, TestSpliceAlgorithm2) 
{ 
    testSplice(100, 20);
}
TEST_F(AFLMutatorTest, TestSpliceAlgorithm3) 
{ 
    testSplice(5, 2);
}
TEST_F(AFLMutatorTest, TestSpliceAlgorithm4) 
{ 
    testSplice(20, 100);
}
TEST_F(AFLMutatorTest, TestSpliceAlgorithm_Short1) 
{ 
    testSplice(1, 10);
}
TEST_F(AFLMutatorTest, TestSpliceAlgorithm_Short2) 
{ 
    testSplice(10, 1);
}
