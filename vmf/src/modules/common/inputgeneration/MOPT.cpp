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

#include "MOPT.hpp"
#include "MOPTSwarm.hpp"
#include "MutatorModule.hpp"
#include "RuntimeException.hpp"
#include "Logging.hpp"
#include <iomanip>

using namespace vmf;

/**
 * @brief Construct a new MOPT object.
 * 
 * @param _mutators the vector of MutatorModules used for mutation
 * @param _numSwarms the number of swarms to use
 * @param _pilotPeriod the length of the pilot phase
 * @param _corePeriod the length of the core phase
 * @param _pMin the percent of the probability space that is evenly distruted among mutators (rather than controlled by MOPT)
 */
MOPT::MOPT(std::vector<MutatorModule*>* _mutators, int _numSwarms, int _pilotPeriod, int _corePeriod, double _pMin)
{

    mutators = _mutators;
    numMutators = mutators -> size();
    numSwarms = _numSwarms;
    pilotPeriod = _pilotPeriod;
    corePeriod = _corePeriod;
    currentSwarm = 0;
    currentMode = PILOT_MODE;
    swarms = new std::vector<MOPTSwarm*>();
    for (unsigned int i = 0; i < numSwarms; i++)
    {
	    MOPTSwarm *s = new MOPTSwarm(numMutators);
	    swarms -> push_back(s);
    }

    G_best = new double[numMutators];
    finds_total = new int[numMutators];
    finds_iteration = new int[numMutators];
    execs_total = new int[numMutators];
    execs_iteration = new int[numMutators];
    execsThisIteration = 0;
    for (unsigned int i = 0; i < numMutators; i++)
    {
        finds_total[i] = 0;
        finds_iteration[i] = 0;
        execs_total[i] = 0;
        execs_iteration[i] = 0;
        G_best[i] = 0.5;
    }

    // Configure parameter settings. We use the same values as AFL++ where applicable.
    g_now = 0;
    g_max = 5000;
    v_max = 1.00;
    w_init = 0.9;
    w_end = 0.3;

    /*
     * Note that v_min should not be a constant value as in AFL-MOPT, because we must handle
     * any number of mutators. Instead, we assign 30% of the probability space evenly
     * over all mutators, then let MOPT control the other 70%. These values match what 
     * AFL++ does on the specific number of mutators that it uses. 
     * Alternatively, providing a manual pMin value can override this behavior with
     * a chosen value for more control.
     */
    if (_pMin == 0)
	v_min = 0.30 / numMutators; // 30% is spread evenly, 70% is decided by MOPT
    else
	v_min = _pMin;

    rand = VmfRand::getInstance();
}

MOPT::~MOPT()
{
    for (unsigned int i = 0; i < numSwarms; i++)
    {
	    MOPTSwarm* s = swarms->at(i);
	    delete s;
    }
    swarms -> clear();
    delete swarms;
    
    delete[] G_best;
    delete[] finds_iteration;
    delete[] finds_total;
    delete[] execs_iteration;
    delete[] execs_total;
}


/**
 * @brief The main interface exposed to the InputGenerator, it is called periodically
 * to update MOPT about how many testcases have been run in the current mode.
 *
 * MOPT uses this information to decide when to switch between swarms, modes,
 * and when to run an iteration of the PSO updating algorithm.
 *
 * @param numTestCases the number of testcases that have been run.
 * @param allowPrint whether or not MOPT may print status message to stdout
 */
void MOPT::ranTestCases(int numTestCases, bool allowPrint)
{
    execsThisIteration += numTestCases;

    // Then either switch swarms or switch modes
    if (currentMode == PILOT_MODE && execsThisIteration >= pilotPeriod)
    {
        // Recalc fitness on this swarm
        (swarms -> at(currentSwarm)) -> updateFitness();
        
        // In PILOT_MODE, we cycle through all the swarms.
        currentSwarm++;
        LOG_DEBUG << "Switched to swarm " << currentSwarm;

        // If we hit the last swarm, then we switch to CORE_MODE and
        // use whichever swarm was the most fit this cycle.
        if (currentSwarm == numSwarms)
        {
            currentMode = CORE_MODE;
            LOG_DEBUG << "Switched to CORE_MODE.";

            // Pick the highest fitness swarm.
            double bestFitness = 0;
            for (unsigned int i = 0; i < numSwarms; i++)
            {
                MOPTSwarm* s = swarms->at(i);
                double thisFitness = s -> getSwarmFitness();
                if (thisFitness > bestFitness)
                {
                    currentSwarm = i;
                    bestFitness = thisFitness;
                }
            }

            // If all swarms have a fitness of 0, then pick a swarm randomly.
            // This can happen late in fuzzing when new testcases become rare.
            if (bestFitness == 0)
                currentSwarm = rand -> randBelow(numSwarms);

            if (allowPrint)
            {
                printSwarmWeights();
                LOG_INFO << "Picked swarm " << currentSwarm + 1 << " as the most fit swarm for core mode (fitness = " << bestFitness << ")";
            }
        }

        execsThisIteration = 0;
        
    }
    else if (currentMode == CORE_MODE && execsThisIteration >= corePeriod)
    {
        // When we've finished a batch in CORE_MODE using the most efficient swarm,
        // we run a PSO algorithm update, then switch back to Pilot mode to keep
        // testing/learning from all the swarms.
        LOG_DEBUG << "Running a PSO update.";
        updatePSO();
        LOG_DEBUG << "Set back to PILOT_MODE.";
        currentMode = PILOT_MODE;
        currentSwarm = 0;
        execsThisIteration = 0;
    }
}


/**
 * @brief Runs the PSO updating algorithm at the end of one complete
 * iteration of the MOPT pilot + core periods. This function calculates
 * the new G_Best values then calls updatePSO on each swarm.
 */
void MOPT::updatePSO()
{

    // The g value is not mentioned in the MOPT paper. It represents a slowly
    // decreasing modifier on the w_now value, which causes the magnitude of
    // change incurred by the PSO update to go down over time.
    g_now++;
    if (g_now > g_max)
	    g_now = 0;
    
    w_now = (w_init - w_end) * (g_max - g_now) / g_max + w_end;

    LOG_DEBUG << "g_now: " << g_now << ", w_now: " << w_now;

    // Here we calculate G_best for each mutator, which is the fraction
    // of findings from that mutator compared to all findings.
    int totalFinds = 0;
    for (unsigned int i = 0; i < numMutators; i++)
	    totalFinds += finds_total[i];
    
    for (unsigned int i = 0; i < numMutators; i++)
    {
        if (finds_total[i] > 0)
            G_best[i] = (double) finds_total[i] / totalFinds;
        LOG_DEBUG << "G_Best[" << i << "] = " << G_best[i];
    }

    // Next, perform a PSO update on each swarm using the new G_best
    for (unsigned int i = 0; i < numSwarms; i++)
    {
        MOPTSwarm* s = swarms->at(i);
        s -> updatePSO(G_best, w_now, v_min, v_max);
    }

    // Reset iteration counts
    for (unsigned int i = 0; i < numMutators; i++)
    {
        finds_iteration[i] = 0;
        execs_iteration[i] = 0;
    }
}

/**
 * @brief Updates the exec statistics for a mutator
 * 
 * @param mutator the chosen mutator
 */
void MOPT::updateExecCount(int mutator)
{
    execs_total[mutator]++;
    execs_iteration[mutator]++;
    swarms->at(currentSwarm)->updateExecCount(mutator);
}

/**
 * @brief Updates the findings statistics for a mutator
 * 
 * @param mutator the chosen mutator
 */
void MOPT::updateFindingsCount(int mutator)
{
    finds_iteration[mutator]++;
    finds_total[mutator]++;
    swarms->at(currentSwarm)->updateFindingsCount(mutator);
}

/**
 * @brief Picks a mutator from the currently selected swarm.
 * 
 * @return the chosen mutator
 */
int MOPT::pickMutator()
{
    return swarms->at(currentSwarm)->pickMutator();
}

/**
 * @brief Prints out the mutator weights on each swarm as well as each
 * swarm's fitness. This is called once per full iteration of pilot and
 * core modes.
 */
void MOPT::printSwarmWeights()
{

    // Print a header row, a label and then 1 column for each swarm.
    char formattedTitle[32];
    snprintf(formattedTitle, sizeof(formattedTitle), "%-26s", "Mutator");
    std::string swarmHeader = formattedTitle;
    for (unsigned int i = 0; i < numSwarms; i++)
    {
        std::string swarmName = "Swarm" + std::to_string(i + 1);
        char formattedSwarmName[32];
        snprintf(formattedSwarmName, sizeof(formattedSwarmName), "%11s", swarmName.c_str());
        swarmHeader += formattedSwarmName;
    }
    LOG_INFO << swarmHeader;

    // Print each mutator's weight in each swarm
    for (unsigned int i = 0; i < numMutators; i++)
    {
        char formatted_name[32];
        snprintf(formatted_name, sizeof(formatted_name), "%-26s", (*mutators)[i]->getModuleName().c_str());
        std::string row = formatted_name;
        for (unsigned int j = 0; j < numSwarms; j++)
        {
            char formatted_weight[16];
            MOPTSwarm* s = swarms -> at(j);
            snprintf(formatted_weight, sizeof(formatted_weight), "%10.2f%%", s -> getMutatorWeight(i) * 100);
            row += formatted_weight;
        }
        LOG_INFO << row;
    }

    // Print out swarm fitness
    snprintf(formattedTitle, sizeof(formattedTitle), "%-26s", "Fitness");
    std::string row = formattedTitle;
    for (unsigned int i = 0; i < numSwarms; i++)
    {
        MOPTSwarm* s = swarms -> at(i);
        char formattedFitness[32];
        snprintf(formattedFitness, sizeof(formattedFitness), "%11.4f", s -> getSwarmFitness());
        row += formattedFitness;
    }
    LOG_INFO << row;
}
