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
 * ===========================================================================*/#include <stdint.h>
#include <map>
#include <set>
#include <string>

/**
 * @brief Expose runtime class for Frida instrumentation. 
 * This class exposes the instrumentation run-time API.  
 * 
 */
 class VMFFridaInstrumenter 
{
    private:
    public:
    /** @brief Instatiate the run-time on an AFL style map */
    VMFFridaInstrumenter(uint8_t *trace_bits, uint64_t *prev_pc, const size_t *_nTest, std::set<std::string> &instrumentNames, bool debug = false);

    /** @brief prevent copy ctor */
    VMFFridaInstrumenter(VMFFridaInstrumenter &other) = delete;
    /** @brief prevent assignment. */
    void operator=(const VMFFridaInstrumenter &) = delete;    

    /** @brief Enable the instrumentation */
    void Enable( void );
    /** @brief Provide an activation on the given target function */
    void Activate(const void *target);
    /** @brief Deactivate the instrumentation */
    void Deactivate( void );
    /** @brief Disable instrumentation */
    void Disable( void );
    /** @brief Dump instrumentation meta data to the given ostream in JSON format */
    void DumpMeta(std::ostream &mapMetaFile);
};
