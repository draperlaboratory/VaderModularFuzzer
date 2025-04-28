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
#include <string>

namespace vmf {
/**
 * @brief Wrapper class to encapsulate OS-specific behaviors
 * 
 */
class OSAPI
{
    public:
        /**
         * @brief Returns the singleton instance
         * 
         * @return OSAPI& the singleton
         */
        static OSAPI& instance();

        /**
         * @brief Loads the provided shared library by name
         * 
         * @param pathToLibrary 
         * @return void* the handle to the loaded library
         * @throws a RuntimeException if the library can't be loaded
         */
        virtual void* openDLL(std::string pathToLibrary) = 0;

        /**
         * @brief Closes the provided shared library
         * 
         * @param handle the handle to the library that was returned by openDLL
         */
        virtual void closeDLL(void* handle) = 0;

        /**
         * Parses command line options using linux getopt-style parsing
         * See: https://www.man7.org/linux/man-pages/man3/getopt.3.html
         * @param argc the number of arguments (size of argv)
         * @param argv the list of arguments to parse
         * @param optstring the getopt-formatted option string, describing the supported options
         */
        virtual int getOption(int argc, char* argv[], const char* optstring) = 0;

        /**
         * Call after getOption to retrieve the argument associated with the option
         * @returns the argument
         */
        virtual std::string getOptionArg() = 0;

        /**
         * @brief Returns the current process ID
         * 
         * @return int the process ID
         */
        virtual int getProcessID() = 0;
        
        /**
         * @brief Returns the host name of the current system
         * If the hostname can't be retrieved, this returns "UNKNOWN_HOST"
         * and logs an error message with details of the source of the error.
         *
         * @return string the hostname
         */
        virtual std::string getHostname() = 0;

        /**
         * @brief Retrieve the path of the currently running executable
         * 
         * @return std::string the path
         */
        virtual std::string getExecutablePath() = 0;

        /**
         * @brief Utility method to unzip the specified file using the command line unzip utility
         * 
         * This method does require an unzip utility to be installed.
         * 
         * @param zipFilePath the path to the zip file to unzip
         * @param outputDir the output directory to write to (the directory will be created if it does not exist)
         * @return true if unzip was successful, false otherwise
         */
        virtual bool commandLineUnzip(std::string zipFilePath, std::string outputDir) = 0;

        /**
         * @brief Utility method to zip up all the files in a directory (using the command line zip utility)
         * 
         * This method does require an zip utility to be installed.  The foldername will not be included
         * in the resulting zip file.
         * 
         * @param zipFilePath the path to the output zipfile
         * @param inputDir the input directory to read the files from
         * @return true if zip was successful, false otherwise
         */
        virtual bool commandLineZip(std::string zipFilePath, std::string inputDir) = 0;

        virtual ~OSAPI() {};
};
}
