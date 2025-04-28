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
#include <iostream> 
#include <plog/Log.h> 
#include "plog/Initializers/RollingFileInitializer.h"
#include <plog/Init.h>
#include <plog/Formatters/CsvFormatter.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Appenders/ConsoleAppender.h>
#include <plog/Appenders/RollingFileAppender.h>
#include "ConfigInterface.hpp"

namespace vmf 
{

/**
 * @brief Logger services for VMF
 * To initialize, call initConsoleLog() follwed by init().
 * The console log can be initialized without configuration information
 * as soon as the software is started.
 */
class Logging
{
public:
    static void initConsoleLog();
    static void init(ConfigInterface& config);
    static void shutdown();

protected:
    static plog::Severity convertToLogLevel(int level);

    ///True if the logger has been initialized, false otherwise
    static bool initialized;
};

}