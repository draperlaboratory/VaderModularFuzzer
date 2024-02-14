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
#include "BaseException.hpp"
#include "Logging.hpp"
#include "VaderApplication.hpp"

#include <signal.h>
#include <iostream>


//License repeated for automatic inclusion in doxygen documentation
/*! \mainpage Vader Module Fuzzer (VMF)
 * Vader Modular Fuzzer<br>
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.<br>
 * <vader@draper.com><br>
 *
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * @license GPL-3.0-or-later <https://spdx.org/licenses/GPL-3.0-or-later>
 */

using namespace vader;

static VaderApplication* vaderApplication;

void abort_signal(int)
{
    vaderApplication->stop(); //Upon Ctrl+C, call shutdown();
}


int main(int argc, char** argv)
{
    int res = 1; // default to an error return
    
    std::ios::sync_with_stdio(false);

    try
    {
        vaderApplication = new VaderApplication();
        bool valid = vaderApplication->init(argc, argv);
        if(valid)
        {
            LOG_INFO << "----RUNNING VADER----";
            //Handler for Ctrl+C signal to shutdown controller in an orderly manner
            signal(SIGINT, abort_signal);

            vaderApplication->run();

            res = 0; // signal success
        }

        //Run will only exit once shutdown signal is processed
        delete vaderApplication;
    }
    catch(BaseException e)
    {
        LOG_ERROR << "Vader Exception: " << e.getReason();
    }
    catch(const std::exception& e)
    {
        LOG_ERROR << e.what();
    }
    catch(const char* error)
    {
        LOG_ERROR << error;
    }
    catch(...)
    {
        LOG_ERROR << "Unknown error";
    }

    return res;
}
