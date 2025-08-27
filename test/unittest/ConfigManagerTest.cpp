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
#include "ConfigManager.hpp"
#include "ModuleManager.hpp"

using namespace vmf;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

#define BASIC "test/unittest/inputs/ConfigManagerTest/basicModules.yaml"
#define CLASS_SET "test/unittest/inputs/ConfigManagerTest/CoreClassSet.yaml"
#define SUT "test/unittest/inputs/ConfigManagerTest/fakeSUT.yaml"

TEST(ConfigManagerTest, MissingAnchors)
{
    std::vector<std::string> filenames_invalid = {BASIC,CLASS_SET};
    ModuleManager modules;
    ConfigManager mgr(filenames_invalid, &modules);
    try
    {
        mgr.readConfig();
        FAIL();
    }
    catch(RuntimeException e)
    {
        //Expected error
    }
}

TEST(ConfigManagerTest, TestOrderingOfInputs)
{
    std::vector<std::string> filenames = {BASIC,CLASS_SET,SUT};
    std::vector<std::string> filenames2 = {BASIC,SUT,CLASS_SET};
    std::vector<std::string> filenames3 = {SUT,CLASS_SET,BASIC};
    std::vector<std::string> filenames4 = {SUT,BASIC,CLASS_SET};
    std::vector<std::string> filenames5 = {CLASS_SET,SUT,BASIC};
    std::vector<std::string> filenames6 = {CLASS_SET,BASIC,SUT};
    ModuleManager modules;
    ConfigManager mgr(filenames, &modules);
    mgr.readConfig();

    ConfigManager mgr2(filenames2, &modules);
    mgr2.readConfig();

    ConfigManager mgr3(filenames, &modules);
    mgr.readConfig();

    ConfigManager mgr4(filenames, &modules);
    mgr.readConfig();

    ConfigManager mgr5(filenames, &modules);
    mgr.readConfig();

    ConfigManager mgr6(filenames, &modules);
    mgr.readConfig();
}