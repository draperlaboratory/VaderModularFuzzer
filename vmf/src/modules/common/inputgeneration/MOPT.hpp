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

#pragma once
#include "MOPTSwarm.hpp"
#include "MutatorModule.hpp"
#include <vector>

namespace vmf
{

/** 
 * An enum type representing which mode the MOPT module is currently in.
 * In the pilot mode, each swarm is tested for efficacy to determine which
 * is best. In the core mode, the most efficient swarm is used for a longer
 * period of time to exploit the learned knowledge. 
 */
enum MOPT_Mode { PILOT_MODE, CORE_MODE};

/**
 * @brief The MOPT class represents an instance of the MOPT mutation scheduler
 * running for an InputGenerator. It manages a number of MOPT Swarms
 * and records global information about mutator success (G_Best). It records
 * the current mode and is responsible for mode switching.
 *
 * To use it, an InputGenerator calls pickMutator to determine which mutator
 * it should use. The MOPT object must be alerted when new testcases are executed
 * and new findings are discovered for it to maintain statistics and trigger mode
 * switching.
 */
class MOPT
{
public:
    MOPT(std::vector<MutatorModule*>* mutators, int numSwarms, int pilotPeriod, int corePeriod, double pMin);
    ~MOPT();
    int pickMutator();
    void updateExecCount(int mutator);
    void updateFindingsCount(int mutator);
    void ranTestCases(int numTestCases, bool allowPrint);
    void printSwarmWeights();
private:
    void updatePSO();    
    std::vector<MutatorModule*>* mutators; // A pointer to the list of mutators used in the input generator
    unsigned int numSwarms;
    unsigned int numMutators;
    unsigned int pilotPeriod, corePeriod;
    std::vector<MOPTSwarm*>* swarms;
    unsigned int currentSwarm;
    MOPT_Mode currentMode;
    unsigned int execsThisIteration;
    int* finds_total, *finds_iteration;
    int* execs_total, *execs_iteration;
    double* G_best;
    double w_now, w_init, w_end;
    double v_min, v_max;
    int g_now, g_max;
};
}