/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2026 The Charles Stark Draper Laboratory, Inc.
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
#include <string>
#include <filesystem>
#include <regex>
#include <vector>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

namespace vmf {

/**
 * @brief Helper class for unit testing modules parsing the EventLog.txt for events.
 * 
 * Provides multiple regex parsing functions to look for defined events in the EventLog.txt
 */
class LogFileUtil {
public:
    /** @brief Get the time it took to calibrate from the EventLog.txt using pattern: `Testcase \d+, size= \d+, time taken: (\d+) us` */
    static int getCalibrationTime(std::string log_file);
    static std::string getLatestLog(std::string logs_dir);
    static bool latestLogPredicate(const fs::directory_entry& a, const fs::directory_entry& b);
    static std::vector<fs::directory_entry> getAllLogs(std::string logs_dir);
    static bool getProofOfRetry(std::string log_file);
    static bool getProofOfHeuristic(std::string log_file);
    static bool getProofOf(std::string log_file, const std::string& event);
};
}