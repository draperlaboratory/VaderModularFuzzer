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
#include "AFLFlipBitMutator.hpp"
#include "AFLFlip2BitMutator.hpp"
#include "MOPT.hpp"
#include "MOPTSwarm.hpp"

using namespace vmf;

TEST(MOPTTest, testNormalize)
{
    // Create an MOPTSwarm with 5 mutators
    MOPTSwarm* s = new MOPTSwarm(5);

    // Validate that the 5 random starting weights sum to 1
    float probabilitySum = 0;
    for (int i = 0; i < 5; i++)
    {
	probabilitySum += s -> getMutatorWeight(i);
    }
    
    EXPECT_NEAR(probabilitySum, 1.0, 0.0001);

    delete s;
}

TEST(MOPTTest, testFitness)
{

    // Create an MOPTSwarm with 2 mutators
    MOPTSwarm* s = new MOPTSwarm(2);
    
    // Drive the swarm with both executions and finds
    
    // 100 executions on each mutator
    for (int i = 0; i < 100; i++)
    {
	s -> updateExecCount(0);
	s -> updateExecCount(1);	
    }

    // 10 finds, all on mutator 0
    for (int i = 0; i < 10; i++)
    {
	s -> updateFindingsCount(0);
    }

    s -> updateFitness();
    float fitness = s -> getSwarmFitness();

    // Validate that fitness is 5% (10/200 = 0.05)
    EXPECT_NEAR(fitness, 0.05, 0.0001);

    delete s;
}

TEST(MOPTTest, testPickBetterMutator)
{

    std::vector<MutatorModule*>*mutators = new std::vector<MutatorModule*>();
    mutators -> push_back(new AFLFlipBitMutator("mutator1"));
    mutators -> push_back(new AFLFlip2BitMutator("mutator2"));
	
    // Create an MOPT with 2 mutators and short pilot and core periods
    MOPT * mopt = new MOPT(mutators, 2, 10, 10, 0);

    // Put in 1 hit on each mutator, required for MOPT to update LBest
    mopt -> updateExecCount(0);
    mopt -> updateExecCount(1);
    mopt -> updateFindingsCount(0);
    mopt -> updateFindingsCount(1);
    
    // Drive MOPT over 100 cycles to prefer mutator 0.
    // We periodically sample from it and collect stats on its choices.
    int selected0 = 0;
    int selected1 = 0;
    for (int i = 0; i < 100; i++)
    {
	// Apply even mix of mutators execs, but all finds from mutator 0
	for (int j = 0; j < 5; j++)
	{
	    mopt -> updateExecCount(0);
	    mopt -> updateExecCount(1);
	    mopt -> updateFindingsCount(0);
	}

	//  Update MOPT, no printing while testing
	mopt -> ranTestCases(10, false);

	// Sample from mutator distribution
	for (int i = 0; i < 10; i++)
	{
	    int chosenMutator = mopt -> pickMutator();
	    EXPECT_TRUE(chosenMutator == 0 || chosenMutator == 1);
	    if (chosenMutator == 0)
		selected0++;
	    if (chosenMutator == 1)
		selected1++;
	}
    }

    // Lastly, we see how often it picked mutator 0
    float selected0Percent = 100.0 * (float) selected0 / ((float) selected0 + selected1);

    // We expect it was picked most of the time, at least lower bound of 55% to handle stochastic nature of sampling.
    // Typically it's at least 70% or so.
    EXPECT_GT(selected0Percent, 55.0);

    for(MutatorModule* m: *mutators)
    {
        delete m;
    }
    mutators -> clear();
    delete mutators;
    delete mopt;
}
