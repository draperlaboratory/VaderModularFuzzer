/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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

namespace vader
{

/**
 * @brief A swarm in the MOPT PSO algorithm. Each swarm maintains a weight 
 * (probability) for each mutator and a velocity to use for PSO updating, as 
 * well as a local memory of which weights have been the best (L_Best) for
 * each mutator in the past.
 *
 * Each swarm records statistics about the number of executions that were run
 * and how many interesting finds were discovered. It has a fitness value 
 * representing how many finds per execution it has discovered.
 *
 * Swarms are created and managed by the MOPT class.
 * 
 */
class MOPTSwarm
{
public:
    MOPTSwarm(int numMutators);
    ~MOPTSwarm();
    int pickMutator();
    void normalize();
    void updateExecCount(int mutator);
    void updateFindingsCount(int mutator);
    void updatePSO(double * G_best, double w_now, double v_min, double v_max);
    double getMutatorWeight(int mutator);
    double getSwarmFitness();
    int getFinds(int mutator);
    int getExecs(int mutator);
    void updateFitness();
private:
    unsigned int numMutators;
    double fitness;
    int* finds_total, *finds_iteration;
    int* execs_total, *execs_iteration;
    double* x_now;
    double* v_now;
    double* L_best;
    double* eff_best;
};
}
