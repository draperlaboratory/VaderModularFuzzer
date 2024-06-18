/* =============================================================================
 * Copyright (c) 2023 Vigilant Cyber Systems
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

#include "string"
#include "Gramatron.hpp"
#include "Logging.hpp"

namespace vmf
{
/**
 * @brief PDA singleton used for generating inputs based on Context Free Grammar Push-down Automata representation
 * 
 */
class PDA
{
public:
    PDA(PDA &other) = delete;

    void operator=(const PDA &) = delete;

    static PDA* GetInstance();

    static PDA* CreateInstance(const std::string& path);

    /**
    * @brief Gets the final state for the PDA
    *
    */
    int final_state() const{
        return final_state_;
    }

    /**
    * @brief Gets the initial state for the PDA
    *
    */
    int init_state() const{
        return init_state_;
    }

    /**
    * @brief Gets the number of states for the PDA
    *
    */
    int num_states() const{
        return num_states_;
    }

    /**
    * @brief Gets the pointer to the state array for the PDA
    *
    */
    pdaState* state_ptr() const{
        return state_ptr_;
    }

private:
    PDA();

    static PDA* pda_;

    pdaState* state_ptr_;
    int final_state_,init_state_,num_states_;
};
}


