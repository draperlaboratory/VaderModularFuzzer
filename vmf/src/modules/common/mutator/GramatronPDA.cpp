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
#include "GramatronPDA.hpp"

#include "string"
#include "json11.hpp"

using namespace vmf;

PDA* PDA::pda_ = nullptr;

/**
 * @brief Returns the singleton PDA pointer
 */
PDA* PDA::GetInstance() {
    return pda_;
}

/**
 * @brief Creates the singleton PDA pointer
 *
 * @param path the path to the json representation of the PDA for the grammar in use
 */
PDA* PDA::CreateInstance(const std::string &path) {
    if(pda_ == nullptr){
        int trigger_len;

        pda_ = new PDA();

        std::ifstream f(path);
        std::string pdaString;

        if(f){
            std::ostringstream ss;
            ss << f.rdbuf();
            pdaString = ss.str();
        } else {
            LOG_ERROR << "Unable to open PDA file: " << path;
        }

        f.close();

        std::string err;

        json11::Json pda_object = json11::Json::parse(pdaString,err);

        //Inconsistent json format, num states works just getting the int_value but it doesn't work for this field
        pda_->final_state_ = atoi(pda_object["final_state"].string_value().c_str());
        pda_->init_state_ = atoi(pda_object["init_state"].string_value().c_str());
        int numstates = pda_object["numstates"].int_value() + 1;
        pda_->num_states_ = numstates;

        pda_->state_ptr_ = (pdaState *) calloc(numstates,sizeof (pdaState));

        for(auto ci = pda_object["pda"].object_items().begin(); ci != pda_object["pda"].object_items().end(); ++ci) {
            pdaState* state_ptr;
            trigger* trigger_ptr;
            int offset;

            trigger_len = (int) ci->second.array_items().size();

            // Get the correct offset into the pda to store state information
            state_ptr = pda_->state_ptr_;
            offset = atoi(ci->first.c_str());
            state_ptr += offset;

            // Store state string
            state_ptr->stateName = offset;

            // Create trigger array of structs
            state_ptr->trigger_len = trigger_len;
            trigger_ptr = (trigger *)calloc(trigger_len, sizeof(trigger));
            state_ptr->ptr = trigger_ptr;

            for (auto cii = ci->second.array_items().begin(); cii != ci->second.array_items().end(); ++cii) {
                // Get all the trigger trigger attributes
                trigger_ptr->id = strdup((const char *) cii->array_items().at(0).string_value().c_str());

                trigger_ptr->dest = atoi((const char *) cii->array_items().at(1).string_value().c_str());

                const char* term = (const char *) cii->array_items().at(2).string_value().c_str();

                if(! strcmp("\\n", term)) {
                    trigger_ptr->term = strdup("\n");
                }
                else {
                    trigger_ptr->term = strdup(term);
                }

                trigger_ptr->term_len = strlen(trigger_ptr->term);

                trigger_ptr++;
            }
        }
    }
    return pda_;
}

PDA::PDA() {
    this->final_state_ = -1;
    this->init_state_ = -1;
    this->num_states_ = -1;
    this->state_ptr_ = nullptr;
}

