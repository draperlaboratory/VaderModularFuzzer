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

#include "gtest/gtest.h"
#include "StorageRegistry.hpp"
#include "SimpleStorage.hpp"
#include "StorageKeyHelper.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

TEST(StorageRegistryTest, StorageKeyHelperTest)
{
    int index = 0xF12345F;
    int mask = 0xA; //1010
    int handle = StorageKeyHelper::addTypeToIndex(index, mask);
    GTEST_COUT << "Handle is:" << handle << "\n";

    int returnedIndex = StorageKeyHelper::getIndex(handle);
    ASSERT_EQ(returnedIndex, index) << "Returned index of " << returnedIndex << " does not equal expected " << index;

    int returnedMask = StorageKeyHelper::getType(handle);
    ASSERT_EQ(returnedMask, mask) << "Returned mast of " << returnedMask  << " does not equal expected " << mask;

    SimpleStorage* storage = new SimpleStorage("storage");

    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    // Default value for this key is 5 (this is the sort by key)
    int int_key = registry->registerIntKey(
        "TEST_INT",
        StorageRegistry::READ_WRITE,
        5
    );

    GTEST_COUT << "TEST_INT Handle is:" << int_key << "\n";
    int type = StorageKeyHelper::getType(int_key);
    ASSERT_EQ(type, 1) << "Type not as expected, got: " << type; //INT_TYPE mask is 1

    int index2 = StorageKeyHelper::getIndex(int_key);
    ASSERT_EQ(index2, 0) << "Index not as expected, got: " << index2; //In the current implementation, the first value is registered at index 0

    int float_key = registry->registerKey("TEST_FLOAT", StorageRegistry::FLOAT, StorageRegistry::READ_WRITE);
    GTEST_COUT << "TEST_FLOAT Handle is:" << float_key << "\n";
    type = StorageKeyHelper::getType(float_key);
    ASSERT_EQ(type, 4) << "Float type not as expected, got: " << type; //FLOAT_TYPE_MASK is 4

    index2 = StorageKeyHelper::getIndex(float_key);
    ASSERT_EQ(index2, 0) << "Float Index not as expected, got: " << index2; //In the current implementation, the first value is registered at index 0

    delete storage;
    delete registry;
}

TEST(StorageRegistryTest, testDefaults)
{
    SimpleStorage* storage = new SimpleStorage("storage");

    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    GTEST_COUT << "Registering int keys\n";

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

    ASSERT_EQ(2,registry->getNumKeys(StorageRegistry::INT));

    GTEST_COUT << "Registering uint keys\n";

    // Default value for this key is 5 (this is the sort by key)
    int uint_key = registry->registerUIntKey(
        "TEST_UINT",
        StorageRegistry::READ_WRITE,
        3000000000
    );

    //This has no default
    int uint_key_no_default = registry->registerKey(
        "TEST_UINT_NO_DEF",
        StorageRegistry::UINT,
        StorageRegistry::READ_WRITE
    );

    ASSERT_EQ(2,registry->getNumKeys(StorageRegistry::UINT));

    GTEST_COUT << "Registering float keys\n";
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

    ASSERT_EQ(2,registry->getNumKeys(StorageRegistry::FLOAT));

    GTEST_COUT << "Registering u64 keys\n";
    //Default values for this key is 100000000000
    int u64_key = registry->registerU64Key( 
        "TEST_U64",
        StorageRegistry::READ_WRITE,
        100000000000
    );

    //This has no default
    int u64_key_no_default = registry->registerKey(
        "TEST_U64_NO_DEF",
        StorageRegistry::U64,
        StorageRegistry::READ_WRITE
    );

    ASSERT_EQ(2,registry->getNumKeys(StorageRegistry::U64));
  
    GTEST_COUT << "Checking int key defaults\n";
    std::vector<int> intDefs = registry->getIntKeyDefaults();
    int int_key_index = StorageKeyHelper::getIndex(int_key);
    int int_key_no_default_index = StorageKeyHelper::getIndex(int_key_no_default);
    ASSERT_EQ(intDefs[int_key_index],5);
    ASSERT_EQ(intDefs[int_key_no_default_index],0);

    GTEST_COUT << "Checking uint key defaults\n";
    std::vector<unsigned int> uintDefs = registry->getUIntKeyDefaults();
    int uint_key_index = StorageKeyHelper::getIndex(uint_key);
    int uint_key_no_default_index = StorageKeyHelper::getIndex(uint_key_no_default);
    ASSERT_EQ(uintDefs[uint_key_index],3000000000);
    ASSERT_EQ(uintDefs[uint_key_no_default_index],0);

    GTEST_COUT << "Checking float key defaults\n";
    std::vector<float> floatDefs = registry->getFloatKeyDefaults();
    int float_key_index = StorageKeyHelper::getIndex(float_key);
    int float_key_no_default_index = StorageKeyHelper::getIndex(float_key_no_default);
    ASSERT_EQ(floatDefs[float_key_index],2.0);
    ASSERT_EQ(floatDefs[float_key_no_default_index],0);

    GTEST_COUT << "Checking u64 key defaults\n";
    std::vector<unsigned long long> u64Defs = registry->getU64KeyDefaults();
    int u64_key_index = StorageKeyHelper::getIndex(u64_key);
    int u64_key_no_default_index = StorageKeyHelper::getIndex(u64_key_no_default);
    ASSERT_EQ(u64Defs[u64_key_index],100000000000);
    ASSERT_EQ(u64Defs[u64_key_no_default_index],0);


    GTEST_COUT << "Validating storage registration\n";
    StorageRegistry* metadata = new StorageRegistry();
        
    storage->configure(registry, metadata);
    bool valid = registry->validateRegistration();
    ASSERT_TRUE(valid);

    GTEST_COUT << "Checking values in an actual storage entry\n";
    try
    {
        StorageEntry* entry = storage->createNewEntry();
        ASSERT_EQ(entry->getIntValue(int_key), 5);
        ASSERT_EQ(entry->getUIntValue(uint_key), 3000000000);
        ASSERT_EQ(entry->getFloatValue(float_key), 2.0);
        ASSERT_EQ(entry->getU64Value(u64_key), 100000000000);
        ASSERT_EQ(entry->getIntValue(int_key_no_default), 0);
        ASSERT_EQ(entry->getUIntValue(uint_key_no_default), 0);
        ASSERT_EQ(entry->getFloatValue(float_key_no_default), 0.0);
        ASSERT_EQ(entry->getU64Value(u64_key_no_default), 0);
    }
    catch(RuntimeException e)
    {
        FAIL() << "Exception:" << e.getReason();
    }
    
    GTEST_COUT << "Calling destructors\n";
    delete storage;
    delete registry;
    delete metadata;
}

TEST(StorageRegistryTest, testDefaultOnSecondRegistration)
{
    SimpleStorage* storage = new SimpleStorage("storage");

    StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    float myFloat = 3.14F; //This has to be a reused value to specify actual equality

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
    int uint_key_no_default = registry->registerKey(
        "TEST_UINT",
        StorageRegistry::UINT,
        StorageRegistry::READ_WRITE
    );

    //Now set one on a subsequent registration
    int uint_key = registry->registerUIntKey(
        "TEST_UINT",
        StorageRegistry::READ_WRITE,
        1000
    );

    //This has no default
    int u64_key_no_default = registry->registerKey(
        "TEST_U64",
        StorageRegistry::U64,
        StorageRegistry::READ_WRITE
    );

    //Now set one on a subsequent registration
    int u64_key = registry->registerU64Key(
        "TEST_U64",
        StorageRegistry::READ_WRITE,
        1000000
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
    int uint_key_2 = registry->registerKey(
        "TEST_UINT_2",
        StorageRegistry::UINT,
        StorageRegistry::READ_WRITE
    );

    //This has no default
    int u64_key_2 = registry->registerKey(
        "TEST_U64_2",
        StorageRegistry::U64,
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
    int int_key_index = StorageKeyHelper::getIndex(int_key);
    int int_key_2_index = StorageKeyHelper::getIndex(int_key_2);
    ASSERT_EQ(intDefs[int_key_index],10);
    ASSERT_EQ(intDefs[int_key_2_index],0);

    std::vector<unsigned int> uintDefs = registry->getUIntKeyDefaults();
    int uint_key_index = StorageKeyHelper::getIndex(uint_key);
    int uint_key_2_index = StorageKeyHelper::getIndex(uint_key_2);
    ASSERT_EQ(uintDefs[uint_key_index],1000);
    ASSERT_EQ(uintDefs[uint_key_2_index],0);

    std::vector<unsigned long long> u64Defs = registry->getU64KeyDefaults();
    int u64_key_index = StorageKeyHelper::getIndex(u64_key);
    int u64_key_2_index = StorageKeyHelper::getIndex(u64_key_2);
    ASSERT_EQ(u64Defs[u64_key_index],1000000);
    ASSERT_EQ(u64Defs[u64_key_2_index],0);

    std::vector<float> floatDefs = registry->getFloatKeyDefaults();
    int float_key_index = StorageKeyHelper::getIndex(float_key);
    int float_key_2_index = StorageKeyHelper::getIndex(float_key_2);
    ASSERT_EQ(floatDefs[float_key_index],myFloat);
    ASSERT_TRUE(floatDefs[float_key_2_index] < 0.0001);
    ASSERT_TRUE(floatDefs[float_key_2_index] > -0.0001);

    StorageRegistry* metadata = new StorageRegistry();

    GTEST_COUT << "Registering metadata values\n";

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

    int meta_uint = metadata->registerUIntKey(
        "TEST_UINT_META",
        StorageRegistry::READ_WRITE,
        456
    );

    int meta_uint_2 = metadata->registerKey(
        "TEST_UINT_META2",
        StorageRegistry::UINT,
        StorageRegistry::READ_WRITE
    );

    int meta_u64 = metadata->registerU64Key(
        "TEST_U64_META",
        StorageRegistry::READ_WRITE,
        999999
    );

    int meta_u64_2 = metadata->registerKey(
        "TEST_U64_META2",
        StorageRegistry::U64,
        StorageRegistry::READ_WRITE
    );

    GTEST_COUT << "Manually checking metadata defaults\n";
  
    std::vector<int> intMetaDefs = metadata->getIntKeyDefaults();
    int meta_int_index = StorageKeyHelper::getIndex(meta_int);
    int meta_int_2_index = StorageKeyHelper::getIndex(meta_int_2);
    ASSERT_EQ(intMetaDefs[meta_int_index],123);
    ASSERT_EQ(intMetaDefs[meta_int_2_index],0);

    std::vector<unsigned int> uintMetaDefs = metadata->getUIntKeyDefaults();
    int meta_uint_index = StorageKeyHelper::getIndex(meta_uint);
    int meta_uint_2_index = StorageKeyHelper::getIndex(meta_uint_2);
    ASSERT_EQ(uintMetaDefs[meta_uint_index],456);
    ASSERT_EQ(uintMetaDefs[meta_uint_2_index],0);

    std::vector<unsigned long long> u64MetaDefs = metadata->getU64KeyDefaults();
    int meta_u64_index = StorageKeyHelper::getIndex(meta_u64);
    int meta_u64_2_index = StorageKeyHelper::getIndex(meta_u64_2);
    ASSERT_EQ(u64MetaDefs[meta_u64_index],999999);
    ASSERT_EQ(u64MetaDefs[meta_u64_2_index],0);
        
    GTEST_COUT << "Initializating storage\n";

    storage->configure(registry, metadata);
    bool valid = registry->validateRegistration();
    ASSERT_TRUE(valid);

    GTEST_COUT << "Checking values in storage entry\n";

    StorageEntry* entry = storage->createNewEntry();
    ASSERT_EQ(entry->getIntValue(int_key), 10);
    ASSERT_EQ(entry->getIntValue(int_key_2), 0);
    ASSERT_EQ(entry->getUIntValue(uint_key), 1000);
    ASSERT_EQ(entry->getUIntValue(uint_key_2), 0);
    ASSERT_EQ(entry->getU64Value(u64_key), 1000000);
    ASSERT_EQ(entry->getU64Value(u64_key_2), 0);
    ASSERT_EQ(entry->getFloatValue(float_key), myFloat);
    ASSERT_TRUE(entry->getFloatValue(float_key_2) < 0.0001);
    ASSERT_TRUE(entry->getFloatValue(float_key_2) > -0.0001);

    GTEST_COUT << "Checking values in metadata entry\n";
    
    StorageEntry& meta = storage->getMetadata();
    ASSERT_EQ(meta.getIntValue(meta_int),123);
    ASSERT_EQ(meta.getIntValue(meta_int_2),0);
    ASSERT_EQ(meta.getUIntValue(meta_uint),456);
    ASSERT_EQ(meta.getUIntValue(meta_uint_2),0);
    ASSERT_EQ(meta.getU64Value(meta_u64),999999);
    ASSERT_EQ(meta.getU64Value(meta_u64_2),0);
    
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
    int uint_key = registry->registerUIntKey(
        "TEST_UINT",
        StorageRegistry::READ_WRITE,
        1000
    );

    //Now set a different default
    try{
        int uint_key2 = registry->registerUIntKey(
            "TEST_UINT",
            StorageRegistry::READ_WRITE,
            5000
        );
        FAIL() << "Exception expected when second uint default value was set";
    } catch (RuntimeException e){
        //This error should happen
    }

    //Set a default
    int u64_key = registry->registerU64Key(
        "TEST_U64",
        StorageRegistry::READ_WRITE,
        1000000
    );

    //Now set a different default
    try{
        int u64_key2 = registry->registerU64Key(
            "TEST_U64",
            StorageRegistry::READ_WRITE,
            5000000
        );
        FAIL() << "Exception expected when second u64 default value was set";
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

TEST(StorageRegistryTest, registerForAllKeys)
{
     StorageRegistry* registry = new StorageRegistry("TEST_INT", StorageRegistry::INT, StorageRegistry::ASCENDING);

    int int_key = registry->registerKey(
        "TEST_INT",
        StorageRegistry::INT,
        StorageRegistry::WRITE_ONLY
    );

    int float_key = registry->registerKey(
        "TEST_FLOAT",
        StorageRegistry::FLOAT,
        StorageRegistry::WRITE_ONLY
    );

    int uint_key = registry->registerKey(
        "TEST_UINT",
        StorageRegistry::UINT,
        StorageRegistry::WRITE_ONLY
    );

    int u64_key = registry->registerKey(
        "TEST_U64",
        StorageRegistry::U64,
        StorageRegistry::WRITE_ONLY
    );

    int buffer_key = registry->registerKey(
        "TEST_BUFFER",
        StorageRegistry::BUFFER,
        StorageRegistry::WRITE_ONLY
    );

    registry->registerToReadAllKeys();

    registry->validateRegistration();

    std::vector<int> intHandles = registry->getKeyHandles(StorageRegistry::INT);
    std::vector<int> uintHandles = registry->getKeyHandles(StorageRegistry::UINT);
    std::vector<int> u64Handles = registry->getKeyHandles(StorageRegistry::U64);
    std::vector<int> floatHandles = registry->getKeyHandles(StorageRegistry::FLOAT);
    std::vector<int> bufferHandles = registry->getKeyHandles(StorageRegistry::BUFFER);

    ASSERT_EQ(intHandles.size(),1);
    ASSERT_EQ(uintHandles.size(),1);
    ASSERT_EQ(u64Handles.size(),1);
    ASSERT_EQ(floatHandles.size(),1);
    ASSERT_EQ(bufferHandles.size(),1);

    ASSERT_EQ(intHandles[0],int_key);
    ASSERT_EQ(uintHandles[0],uint_key);
    ASSERT_EQ(u64Handles[0],u64_key);
    ASSERT_EQ(floatHandles[0],float_key);
    ASSERT_EQ(bufferHandles[0],buffer_key);
}