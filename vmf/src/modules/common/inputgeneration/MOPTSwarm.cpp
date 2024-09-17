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

#include "MOPTSwarm.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include <climits>

using namespace vmf;

/**
 * @brief Construct a new MOPTSwarm object
 * 
 * @param _numMutators the number of mutators for optimization.
 */
MOPTSwarm::MOPTSwarm(int _numMutators)
{

    rand = VmfRand::getInstance();
    numMutators = _numMutators;
    x_now = new double[numMutators];
    v_now = new double[numMutators];
    L_best = new double[numMutators];
    eff_best = new double[numMutators];
    finds_total = new int[numMutators];
    finds_iteration = new int[numMutators];
    execs_total = new int[numMutators];
    execs_iteration = new int[numMutators];
    fitness = 0.0;

    // Initialize starting values
    for (unsigned int i = 0; i < numMutators; i++)
    {
	x_now[i] = (double) rand -> randBelow(1000);
        v_now[i] = 0.1;
        L_best[i] = 0.5;
        eff_best[i] = 0.0;
        finds_total[i] = 0;
        finds_iteration[i] = 0;
        execs_total[i] = 0;
        execs_iteration[i] = 0;
    }

    // Normalize the x_now (random starting weights) so they sum to 1.0
    normalize();
}

MOPTSwarm::~MOPTSwarm()
{
    delete[] x_now;
    delete[] v_now;
    delete[] L_best;
    delete[] eff_best;
    delete[] finds_iteration;
    delete[] finds_total;
    delete[] execs_iteration;
    delete[] execs_total;
}

/**
 * @brief Run the PSO updating algorithm on one particular swarm.
 * See MOPT paper Section 3 equations (3) and (4).
 * 
 * @param G_best the current best global mutator probabilities
 * @param w_now the inertial weight (see paper)
 * @param v_min the minimum mutator probability
 * @param v_max the maximum mutator probability
 */
void MOPTSwarm::updatePSO(double * G_best, double w_now, double v_min, double v_max)
{
    
    // Run the core PSO updating algorithm
    for (unsigned int i = 0; i < numMutators; i++)
    {
        // r1 and r2 are random displacement weights
        float r1 = genRandomWeight();
        float r2 = genRandomWeight();
        v_now[i] = w_now * v_now[i] + r1 * (G_best[i] - x_now[i]) + r2 * (L_best[i] - x_now[i]);
        x_now[i] += v_now[i];
        if (x_now[i] < v_min)
            x_now[i] = v_min;
        if (x_now[i] > v_max)
            x_now[i] = v_max;
    }

    // Whenever we change probabilities, must normalize so they add up to 1.
    normalize();

    // Reset iteration counts
    for (unsigned int i = 0; i < numMutators; i++)
    {
        finds_iteration[i] = 0;
        execs_iteration[i] = 0;
    }
}

/**
 * @brief Calculate the efficiency of each mutator and update the L_Best
 * (local best probability) if appropriate.
 * Additionally, each swarm's fitness is calculated.
 */
void MOPTSwarm::updateFitness()
{
    // Calculate the efficiency of each mutator and update local best if appropriate.
    // Additionally, calculate overall swarm fitness.
    int totalIterationExecs = 0;
    int totalIterationFinds = 0;
    for (unsigned int i = 0; i < numMutators; i++)
    {
        if (execs_iteration[i] > 0)
        {
            double this_eff = ((double) finds_iteration[i]) / execs_iteration[i];
            if (this_eff > eff_best[i])
            {
                eff_best[i] = this_eff;
                L_best[i] = x_now[i];
            }
        }
        LOG_DEBUG << "L_best[" << i << "]=" << L_best[i] << " with best eff " << eff_best[i];
        totalIterationExecs += execs_iteration[i];
        totalIterationFinds += finds_iteration[i];
    }

    if (totalIterationExecs > 0)
	fitness = (double) totalIterationFinds / totalIterationExecs;
}

/**
 * @brief Updates the exec statistics for a mutator
 * 
 * @param mutator the chosen mutator
 */
void MOPTSwarm::updateExecCount(int mutator)
{
    execs_total[mutator]++;
    execs_iteration[mutator]++;
}

/**
 * @brief Updates the findings statistics for a mutator
 * 
 * @param mutator the chosen mutator
 */
void MOPTSwarm::updateFindingsCount(int mutator)
{
    finds_total[mutator]++;
    finds_iteration[mutator]++;
}


/**
 * @brief Normalize so the weights sum to 1 (i.e., are valid probabilities)
 * 
 */
void MOPTSwarm::normalize()
{
    double sum = 0.0;
  
    for (unsigned int i = 0; i < numMutators; i++)
	    sum += x_now[i];
  
    if (sum == 0)
	    throw RuntimeException("MOPT sum of weights was 0.", RuntimeException::UNEXPECTED_ERROR);
  
    for (unsigned int i = 0; i < numMutators; i++)
	    x_now[i] /= sum;
}

// Generate a random float between 0 and 1
float MOPTSwarm::genRandomWeight()
{
    return static_cast <float> (rand->randBelow(INT_MAX)) / static_cast <float> (INT_MAX);
}

/**
 * @brief Use the weights to randomly sample a mutator. Assumes already normalized.
 * 
 * @return int the mutator to use
 */
int MOPTSwarm::pickMutator()
{

    // Roll a random float between 0 and 1
    float roll = genRandomWeight();
    
    // Return which mutator we selected
    float sum = 0.0;
    for (unsigned int i = 0; i < numMutators; i++)
    {
        sum += x_now[i];
        if (sum >= roll)
            return i;
    }
    
    return 0;
}

/**
 * @brief Retrieves the fitness of the swarm
 * 
 * @return the fitness
 */
double MOPTSwarm::getSwarmFitness()
{
    return fitness;
}

/**
 * @brief Retrieves the current weight of the specified mutator
 * 
 * @param mutator the int identifying the mutator of interest
 * @return double the weight
 */
double MOPTSwarm::getMutatorWeight(int mutator)
{
    return x_now[mutator];
}

/**
 * @brief Retrieves the number of interesting testcases found by this mutator.
 * 
 * @param mutator the int identifying the mutator of interest
 * @return int the number of findings
 */
int MOPTSwarm::getFinds(int mutator)
{
    return finds_total[mutator];
}

/**
 * @brief Retrieves the number of total executions run from this mutator.
 * 
 * @param mutator the int identifying the mutator of interest
 * @return int the number of testcases executed produced by this mutator.
 */
int MOPTSwarm::getExecs(int mutator)
{
    return execs_total[mutator];
}
