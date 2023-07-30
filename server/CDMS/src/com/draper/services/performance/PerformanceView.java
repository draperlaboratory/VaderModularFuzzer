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
package com.draper.services.performance;

import java.util.ArrayList;

/***********************************************
 * 
 * Each Cluster State and Total Test Cases on the Cluster
 * Total Registered VMFs on the Cluster
 *
 * Each Scenario State and KPI for Scenario
 * Number of Active VMFs on each Scenario
 *
 ***********************************************/
public class PerformanceView
{
    private int                         regFuzzerSize;
    private int                         unallocFuzzerSize;
    private ArrayList<PerformanceData>  clusters;
    private ArrayList<PerformanceData>  scenarios;
    
    
    public PerformanceView()
    {
        regFuzzerSize  = PerformanceServices.Instance().getRegisteredFuzzers();
    }
 
   public ArrayList<PerformanceData> getClusters()
    {
        return clusters;
    }
    public void setClusters(ArrayList<PerformanceData> clusters)
    {
        this.clusters = clusters;
    }
    public ArrayList<PerformanceData> getScenarios()
    {
        return scenarios;
    }
    public void setScenarios(ArrayList<PerformanceData> scenarios)
    {
        this.scenarios = scenarios;
    }
    
    public int getRegFuzzerSize()
    {
        return regFuzzerSize;
    }

    public int getUnallocFuzzerSize()
    {
        return unallocFuzzerSize;
    }

    public void setUnallocFuzzerSize(int unallocFuzzerSize)
    {
        this.unallocFuzzerSize = unallocFuzzerSize;
    }
}