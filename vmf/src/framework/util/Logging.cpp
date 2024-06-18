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
#include "Logging.hpp"
#include "VmfUtil.hpp"
#include "ConfigInterface.hpp"
#include "RuntimeException.hpp"
#include <regex>

using namespace vmf;

bool Logging::initialized = false;

/**
 * @brief Initialize console logging only
 * This is the first of two initialization methods and should be called
 * by the VMF application during initialization.  Individual users of the
 * logger should just call the static methods.
 * 
 */
void Logging::initConsoleLog()
{
    static plog::ConsoleAppender<plog::TxtFormatter> consoleAppender; 
    plog::init(plog::Severity::info, &consoleAppender);
    initialized = true;
}

/**
 * @brief Initialize other non-console logs
 * This should be called by VMF application during intialization.
 * Individual users of the logger should just call the static methods.
 * 
 * @param config 
 */
void Logging::init(ConfigInterface& config)
{
    if(!initialized)
    {
        initConsoleLog();
    }

    std::string dir = config.getOutputDir() + "/logs";

    VmfUtil::createDirectory(dir.c_str());

    std::string logFile = dir + "/EventLog.txt";

    //Set the log level based on the config file
    plog::Severity logLevel = convertToLogLevel(config.getIntParam(ConfigInterface::VMF_FRAMEWORK_KEY, "logLevel", 3));
    plog::get()->setMaxSeverity(logLevel);

    //Add the file appender
    static plog::RollingFileAppender<plog::CsvFormatter> fileAppender(logFile.c_str(), 10048576, 100); //10MB file size
    plog::get()->addAppender(&fileAppender);
}

/**
 * @brief Helper method to convert config file log level to logger version
 * 
 * @param level 
 * @return int the level, or -1 if the desired level is DEBUG
 */
plog::Severity Logging::convertToLogLevel(int level)
{
    // Set to DEBUG level
    plog::Severity logLevel = plog::Severity::debug;

    if(1 == level) //INFO
    {
        logLevel = plog::Severity::info;
    }
    else if(2 == level) //WARNING
    {
        logLevel = plog::Severity::warning;
    }
    else if(3 == level) //ERROR
    {
        logLevel = plog::Severity::error;
    }
    else if(0 != level) //If anything other the DEBUG, this level is unsupported
    {
        throw RuntimeException("Unsupported log level", RuntimeException::USAGE_ERROR);
    }
    //plog supports additional log levels, but these are not exposed via the Logging interface
   
    return logLevel;
}

/**
 * @brief Shutdown the logger
 * This should be called at application shutdown.
 */
void Logging::shutdown()
{
}

