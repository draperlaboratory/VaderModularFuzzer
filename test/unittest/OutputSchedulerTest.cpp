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
#include "OutputScheduler.hpp"
#include "OutputModule.hpp"
#include "SimpleStorage.hpp"
#include <vector>
#include <chrono>
#include <thread>

using namespace vmf;

class TestOutputModule : public OutputModule
{
public:
    TestOutputModule(std::string name, OutputModule::ScheduleTypeEnum type, int rate) : 
        OutputModule(name)
    {
        myType = type;
        myRate = rate;
        runCount = 0;
    }
    virtual void init(ConfigInterface& config){};
    virtual void registerStorageNeeds(StorageRegistry& registry){};
    virtual void run(StorageModule& storage)
    {
        runCount++;
    }

    virtual OutputModule::ScheduleTypeEnum getDesiredScheduleType()
    {
        return myType;
    }

    virtual int getDesiredScheduleRate()
    {
        return myRate;
    }

    int getRunCount()
    {
        return runCount;
    }

    void resetRunCount()
    {
        runCount = 0;
    }

private:

    OutputModule::ScheduleTypeEnum myType;
    int myRate;
    int runCount;

};

class OutputSchedulerTest : public ::testing::Test {
 protected:
  StorageModule* storage;
  StorageRegistry* registry;

  OutputSchedulerTest() {
    //Storage isn't ever used, so proper initialization is not really needed
    storage = new SimpleStorage("storage");
    registry = new StorageRegistry();
  }

  ~OutputSchedulerTest() override {}

  void SetUp() override {
  }

  void TearDown() override 
  {
    delete registry;
    delete storage;
  }

};  // class OutputSchedulerTest

TEST_F(OutputSchedulerTest, TestErrorHandling) {
    std::vector<OutputModule*> testModules;
    TestOutputModule test1("test1", OutputModule::CALL_EVERYTIME, 0);

    testModules.push_back(&test1);

    OutputScheduler scheduler;
    scheduler.setOutputModules(testModules);

    try
    {
        scheduler.setOutputModules(testModules);
        FAIL() << "Expected exception on second initialization";
    }
    catch(RuntimeException e)
    {
        //This should happen, setOutputModules should only be called once
    }

    TestOutputModule badModule("bad", OutputModule::CALL_ON_NUM_SECONDS, 0);
    testModules.push_back(&badModule);

    OutputScheduler scheduler2;
    try
    {
        scheduler2.setOutputModules(testModules);
        scheduler2.runOutputModules(0,*storage); //rates are not checked until the first call to run modules
        FAIL() << "Expected exception for invalid configuration";
    }
    catch(RuntimeException e)
    {
        //This should happen, setOutputModules should not allow a 0 time
    }

}

TEST_F(OutputSchedulerTest, TestRunEverytime) {
    std::vector<OutputModule*> testModules;
    TestOutputModule test1("test1", OutputModule::CALL_EVERYTIME, 0);
    TestOutputModule test2("test2", OutputModule::CALL_EVERYTIME, 100); //second param should be ignored
    TestOutputModule test3("test3", OutputModule::CALL_EVERYTIME, -100); //second param should be ignored

    //make sure these constructed correctly
    ASSERT_EQ(test1.getDesiredScheduleRate(), 0);
    ASSERT_EQ(test2.getDesiredScheduleRate(), 100);
    ASSERT_EQ(test3.getDesiredScheduleRate(), -100);

    testModules.push_back(&test1);
    testModules.push_back(&test2);
    testModules.push_back(&test3);

    OutputScheduler scheduler;
    scheduler.setOutputModules(testModules);

    //Nothing should have run yet
    ASSERT_EQ(test1.getRunCount(),0);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);

    //Run a few time, make sure the run count increments properly
    for(int i=1; i<10; i++)
    {
        scheduler.runOutputModules(10,*storage);

        ASSERT_EQ(test1.getRunCount(),i);
        ASSERT_EQ(test2.getRunCount(),i);
        ASSERT_EQ(test3.getRunCount(),i);
    }

}

TEST_F(OutputSchedulerTest, TestRunByTCCount) {
    std::vector<OutputModule*> testModules;
    TestOutputModule test1("test1", OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS, 5);
    TestOutputModule test2("test2", OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS, 15); 
    TestOutputModule test3("test3", OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS, 10); 

    testModules.push_back(&test1);
    testModules.push_back(&test2);
    testModules.push_back(&test3);

    OutputScheduler scheduler;
    scheduler.setOutputModules(testModules);

    //Nothing should have run yet
    ASSERT_EQ(test1.getRunCount(),0);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);

    //Only the first module should  run
    scheduler.runOutputModules(5,*storage);

    ASSERT_EQ(test1.getRunCount(),1);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);

    //First and third should run
    scheduler.runOutputModules(5,*storage);

    ASSERT_EQ(test1.getRunCount(),2);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),1);

    //First and second should run
    scheduler.runOutputModules(5,*storage);

    ASSERT_EQ(test1.getRunCount(),3);
    ASSERT_EQ(test2.getRunCount(),1);
    ASSERT_EQ(test3.getRunCount(),1);
    
    //First and third should run
    scheduler.runOutputModules(5,*storage);

    ASSERT_EQ(test1.getRunCount(),4);
    ASSERT_EQ(test2.getRunCount(),1);
    ASSERT_EQ(test3.getRunCount(),2);

}

TEST_F(OutputSchedulerTest, TestRunByTime) {
    std::vector<OutputModule*> testModules;
    TestOutputModule test1("test1", OutputModule::CALL_ON_NUM_SECONDS, 1);
    TestOutputModule test2("test2", OutputModule::CALL_ON_NUM_SECONDS, 2); 
    TestOutputModule test3("test3", OutputModule::CALL_ON_NUM_SECONDS, 3); 

    testModules.push_back(&test1);
    testModules.push_back(&test2);
    testModules.push_back(&test3);

    OutputScheduler scheduler;
    scheduler.setOutputModules(testModules);

    scheduler.runOutputModules(25,*storage);
    //Nothing should have run yet
    ASSERT_EQ(test1.getRunCount(),0);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    scheduler.runOutputModules(25,*storage);

    //Only the 1s test case should have run
    ASSERT_EQ(test1.getRunCount(),1);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);

    scheduler.runOutputModules(25,*storage);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    scheduler.runOutputModules(25,*storage);

    //1s and 2s should have run
    ASSERT_EQ(test1.getRunCount(),2);
    ASSERT_EQ(test2.getRunCount(),1);
    ASSERT_EQ(test3.getRunCount(),0);

    scheduler.runOutputModules(25,*storage);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    scheduler.runOutputModules(25,*storage);

    //1s and 3s should have run
    ASSERT_EQ(test1.getRunCount(),3);
    ASSERT_EQ(test2.getRunCount(),1);
    ASSERT_EQ(test3.getRunCount(),1);
    
    scheduler.runOutputModules(25,*storage);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    scheduler.runOutputModules(25,*storage);

    //1s and 2s should have run
    ASSERT_EQ(test1.getRunCount(),4);
    ASSERT_EQ(test2.getRunCount(),2);
    ASSERT_EQ(test3.getRunCount(),1);

}

TEST_F(OutputSchedulerTest, TestAllTypes) {
    std::vector<OutputModule*> testModules;
    TestOutputModule test1("test1", OutputModule::CALL_EVERYTIME, 0);
    TestOutputModule test2("test2", OutputModule::CALL_ON_NUM_SECONDS, 1); 
    TestOutputModule test3("test3", OutputModule::CALL_ON_NUM_TEST_CASE_EXECUTIONS, 20); 
    TestOutputModule test4("test4", OutputModule::CALL_ONLY_ON_SHUTDOWN, 2); //param should be ignored

    testModules.push_back(&test1);
    testModules.push_back(&test2);
    testModules.push_back(&test3);
    testModules.push_back(&test4);

    OutputScheduler scheduler;
    scheduler.setOutputModules(testModules);

    //Nothing should have run yet
    ASSERT_EQ(test1.getRunCount(),0);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);
    ASSERT_EQ(test4.getRunCount(),0);

    scheduler.runOutputModules(5,*storage);

    //Only the first one should have run
    ASSERT_EQ(test1.getRunCount(),1);
    ASSERT_EQ(test2.getRunCount(),0);
    ASSERT_EQ(test3.getRunCount(),0);
    ASSERT_EQ(test4.getRunCount(),0);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    scheduler.runOutputModules(25,*storage);

    //First 3 should have run
    ASSERT_EQ(test1.getRunCount(),2);
    ASSERT_EQ(test2.getRunCount(),1);
    ASSERT_EQ(test3.getRunCount(),1);
    ASSERT_EQ(test4.getRunCount(),0); //Shutdown module only runs at application shutdown (not tested here)

}