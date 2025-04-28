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
 * ===========================================================================*/
#pragma once
#include "OSAPI.hpp"

namespace vmf {
/**
 * @brief Linux implementation of OSAPI utilities
 * 
 */
class OSAPIImp: public OSAPI
{
    public:
        /**
         * @brief Returns the singleton instance
         * 
         * @return OSAPI& the singleton
         */
        static OSAPI& instance();
        OSAPIImp();
        virtual void* openDLL(std::string pathToLibrary);
        virtual void closeDLL(void* handle);

        virtual int getOption(int argc, char* argv[], const char* optstring);
        virtual std::string getOptionArg();

        virtual int getProcessID();
        virtual std::string getHostname();

        virtual std::string getExecutablePath();

        virtual bool commandLineZip(std::string zipFilePath, std::string inputDir);
        virtual bool commandLineUnzip(std::string zipFilePath, std::string outputDir);

        virtual ~OSAPIImp();
};
}