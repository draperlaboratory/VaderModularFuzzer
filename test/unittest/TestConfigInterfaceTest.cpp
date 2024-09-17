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
#include "TestConfigInterface.hpp"


using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

/* This is is a test of the TestConfigInterface component */
TEST(TestConfigInterfaceTest, testGettersAndSetters)
{
    TestConfigInterface config;
    std::string moduleName = "fakeModuleName"; //Value is ignored by TestConfigInterface

    config.setIntParam("x",123);
    int intVal = config.getIntParam(moduleName,"x");
    ASSERT_EQ(intVal, 123);

    float f = 45.35;
    config.setFloatParam("y",f);
    float f2 = config.getFloatParam(moduleName,"y");
    ASSERT_EQ(f,f2);

    std::string s = "hello";
    config.setStringParam("w",s);
    std::string s2 = config.getStringParam(moduleName, "w");
    ASSERT_EQ(s,s2);

    std::vector<std::string> list = {"a","b"};
    config.setStringVectorParam("z",list);
    std::vector<std::string> list2 = config.getStringVectorParam(moduleName,"z");
    ASSERT_EQ(list.size(),list2.size());
    ASSERT_EQ(list[0],list2[0]);
    ASSERT_EQ(list[1],list2[1]);
   
}