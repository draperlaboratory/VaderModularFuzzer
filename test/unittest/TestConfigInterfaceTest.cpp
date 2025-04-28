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
#include "TestConfigInterface.hpp"


using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

/* This is is a test of the TestConfigInterface component */
TEST(TestConfigInterfaceTest, testGettersAndSetters)
{
    TestConfigInterface config;
    std::string moduleName = "fakeModuleName"; 

    config.setIntParam(moduleName,"x",123);
    int intVal = config.getIntParam(moduleName,"x");
    ASSERT_EQ(intVal, 123);

    float f = 45.35F;
    config.setFloatParam(moduleName,"y",f);
    float f2 = config.getFloatParam(moduleName,"y");
    ASSERT_EQ(f,f2);

    std::string s = "hello";
    config.setStringParam(moduleName,"w",s);
    std::string s2 = config.getStringParam(moduleName, "w");
    ASSERT_EQ(s,s2);

    std::vector<std::string> list = {"a","b"};
    config.setStringVectorParam(moduleName,"z",list);
    std::vector<std::string> list2 = config.getStringVectorParam(moduleName,"z");
    ASSERT_EQ(list.size(),list2.size());
    ASSERT_EQ(list[0],list2[0]);
    ASSERT_EQ(list[1],list2[1]);

    //Now test a second module name
    std::string secondModule = "module2";
    config.setIntParam(secondModule,"x",345);
    int intVal1 = config.getIntParam(moduleName,"x");
    ASSERT_EQ(intVal1, 123);
    int intVal2 = config.getIntParam(secondModule,"x");
    ASSERT_EQ(intVal2, 345);

    std::string sVal = "goodbye";
    config.setStringParam(secondModule,"w",sVal);
    std::string test = config.getStringParam(moduleName, "w");
    ASSERT_EQ(s,test);
    std::string test2 = config.getStringParam(secondModule, "w");
    ASSERT_EQ(sVal,test2);
   
}