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
#include "StorageRegistry.hpp"
#include "SimpleStorage.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

TEST(StorageRegistryTest, testDefaults)
{
    SimpleStorage* storage = new SimpleStorage("storage");

    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    // Default value for this key is 5 (this is the sort by key)
    int int_key = registry->registerIntKey(
        "TEST_INT",
        StorageRegistry::READ_WRITE,
        5
    );

    //This has no default
    int int_key_no_default = registry->registerKey(
        "TEST_INT_NO_DEF",
        StorageRegistry::INT,
        StorageRegistry::READ_WRITE
    );

    //Default values for this key is 2.0
    int float_key = registry->registerFloatKey( 
        "TEST_FLOAT",
        StorageRegistry::READ_WRITE,
        2.0
    );

    //This has no default
    int float_key_no_default = registry->registerKey(
        "TEST_FLOAT_NO_DEF",
        StorageRegistry::FLOAT,
        StorageRegistry::READ_WRITE
    );
  
    std::vector<int> intDefs = registry->getIntKeyDefaults();
    ASSERT_EQ(intDefs[int_key],5);
    ASSERT_EQ(intDefs[int_key_no_default],0);

    std::vector<float> floatDefs = registry->getFloatKeyDefaults();
    ASSERT_EQ(floatDefs[float_key],2.0);
    ASSERT_EQ(floatDefs[float_key_no_default],0);

    StorageRegistry* metadata = new StorageRegistry();
        
    storage->configure(registry, metadata);
    bool valid = registry->validateRegistration();
    ASSERT_TRUE(valid);

    StorageEntry* entry = storage->createNewEntry();
    ASSERT_EQ(entry->getIntValue(int_key), 5);
    ASSERT_EQ(entry->getFloatValue(float_key), 2.0);
    ASSERT_EQ(entry->getIntValue(int_key_no_default), 0);
    ASSERT_EQ(entry->getFloatValue(float_key_no_default), 0.0);
    
    delete storage;
    delete registry;
    delete metadata;
}

TEST(StorageRegistryTest, testDefaultOnSecondRegistration)
{
    SimpleStorage* storage = new SimpleStorage("storage");

    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    float myFloat = 3.14; //This has to be a reused value to specify actual equality

    GTEST_COUT << "Registering values\n";

    //This has no default
    int int_key_no_default = registry->registerKey(
        "TEST_INT",
        StorageRegistry::INT,
        StorageRegistry::READ_WRITE
    );

    //Now set one on a subsequent registration
    int int_key = registry->registerIntKey(
        "TEST_INT",
        StorageRegistry::READ_WRITE,
        10
    );

    //This has no default
    int float_key_no_default = registry->registerKey(
        "TEST_FLOAT",
        StorageRegistry::FLOAT,
        StorageRegistry::READ_WRITE
    );

    //Now set one on a subsequent registration
    int float_key = registry->registerFloatKey( 
        "TEST_FLOAT",
        StorageRegistry::READ_WRITE,
        myFloat
    );

    //This has no default
    int int_key_2 = registry->registerKey(
        "TEST_INT_2",
        StorageRegistry::INT,
        StorageRegistry::READ_WRITE
    );

    //This has no default
    int float_key_2 = registry->registerKey(
        "TEST_FLOAT_2",
        StorageRegistry::FLOAT,
        StorageRegistry::READ_WRITE
    );

    GTEST_COUT << "Manually checking defaults\n";
  
    std::vector<int> intDefs = registry->getIntKeyDefaults();
    ASSERT_EQ(intDefs[int_key],10);
    ASSERT_EQ(intDefs[int_key_2],0);

    std::vector<float> floatDefs = registry->getFloatKeyDefaults();
    ASSERT_EQ(floatDefs[float_key],myFloat);
    ASSERT_TRUE(floatDefs[float_key_2] < 0.0001);
    ASSERT_TRUE(floatDefs[float_key_2] > -0.0001);

    StorageRegistry* metadata = new StorageRegistry();

    GTEST_COUT << "Registering metadata alues\n";

    //Add metadata keys too
    //Now set one on a subsequent registration
    int meta_int = metadata->registerIntKey(
        "TEST_INT_META",
        StorageRegistry::READ_WRITE,
        123
    );

    int meta_int_2 = metadata->registerKey(
        "TEST_INT_META2",
        StorageRegistry::INT,
        StorageRegistry::READ_WRITE
    );

    GTEST_COUT << "Manually checking metadata defaults\n";
  
    std::vector<int> intMetaDefs = metadata->getIntKeyDefaults();
    ASSERT_EQ(intMetaDefs[meta_int],123);
    ASSERT_EQ(intMetaDefs[meta_int_2],0);
        
    GTEST_COUT << "Initializating storage\n";

    storage->configure(registry, metadata);
    bool valid = registry->validateRegistration();
    ASSERT_TRUE(valid);

    GTEST_COUT << "Checking values in storage entry\n";

    StorageEntry* entry = storage->createNewEntry();
    ASSERT_EQ(entry->getIntValue(int_key), 10);
    ASSERT_EQ(entry->getIntValue(int_key_2), 0);
    ASSERT_EQ(entry->getFloatValue(float_key), myFloat);
    ASSERT_TRUE(entry->getFloatValue(float_key_2) < 0.0001);
    ASSERT_TRUE(entry->getFloatValue(float_key_2) > -0.0001);

    GTEST_COUT << "Checking values in metadata entry\n";
    
    StorageEntry& meta = storage->getMetadata();
    ASSERT_EQ(meta.getIntValue(meta_int),123);
    ASSERT_EQ(meta.getIntValue(meta_int_2),0);
    
    delete storage;
    delete registry;
    delete metadata;
}


TEST(StorageRegistryTest, testErrorHandling)
{
    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    //Set a default
    int int_key = registry->registerIntKey(
        "TEST_INT",
        StorageRegistry::READ_WRITE,
        10
    );

    //Now set a different default
    try{
        int int_key2 = registry->registerIntKey(
            "TEST_INT",
            StorageRegistry::READ_WRITE,
            5
        );
        FAIL() << "Exception expected when second int default value was set";
    } catch (RuntimeException e){
        //This error should happen
    }

    //Set a default
    int float_key = registry->registerFloatKey( 
        "TEST_FLOAT",
        StorageRegistry::READ_WRITE,
        4.0
    );

    //Now set a different default
    try{
        int float_key2 = registry->registerFloatKey(
            "TEST_FLOAT",
            StorageRegistry::READ_WRITE,
            5.0
        );
        FAIL() << "Exception expected when second float default value was set";
    } catch (RuntimeException e){
        //This error should happen
    }

    delete registry;
}