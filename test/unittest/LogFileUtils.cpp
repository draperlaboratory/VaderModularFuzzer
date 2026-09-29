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
#include "LogFileUtils.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

using namespace vmf;

bool LogFileUtil::latestLogPredicate(const fs::directory_entry& a, const fs::directory_entry& b)
{
    return a.last_write_time() > b.last_write_time();
}

std::string LogFileUtil::getLatestLog(std::string logs_dir)
{
    std::vector<fs::directory_entry> files;
    for (const auto& entry : fs::directory_iterator(logs_dir))
    {
        if (entry.is_regular_file())
        {
            files.push_back(entry);
        }
    }
    std::sort(files.begin(), files.end(), latestLogPredicate);
    std::string ret = files.empty() ? "" : files.front().path().string();
    return ret;
}

std::vector<fs::directory_entry> LogFileUtil::getAllLogs(std::string logs_dir)
{
    std::vector<fs::directory_entry> files;
    GTEST_COUT << "Gathering logs from " << logs_dir << std::endl;
    for (const auto& entry : fs::directory_iterator(logs_dir))
    {
        if (entry.is_regular_file())
        {
            files.push_back(entry);
        }
    }
    return files;
}

int LogFileUtil::getCalibrationTime(std::string log_file)
{
    std::ifstream log_file_stream(log_file.c_str());
    int calibration_time = 0;
    std::string line;
    std::regex pattern(R"(Testcase \d+, size= \d+, time taken: (\d+) us)");
    std::smatch match;

    bool found = false;
    while(std::getline(log_file_stream, line))
    {
        if (std::regex_search(line, match, pattern))
        {
            calibration_time = std::stoi(match[1].str());
            found = true;
            log_file_stream.close();
            break;
        }
    }
    // ASSERT_TRUE(found) << " Unable to find calibration time in log file: " << log_file;
    return calibration_time;
}

bool LogFileUtil::getProofOfRetry(std::string log_file)
{
    return getProofOf(log_file, R"(Confirming hang with increased timeout \d+ ms)");
}

bool LogFileUtil::getProofOfHeuristic(std::string log_file)
{
    return getProofOf(log_file, R"(USING computed timeout!)");
}

bool LogFileUtil::getProofOf(std::string log_file, const std::string& event)
{
    std::ifstream log_file_stream(log_file.c_str());
    std::string line;
    std::regex pattern(event);
    std::smatch match;

    bool found = false;
    while(std::getline(log_file_stream, line))
    {
        if (std::regex_search(line, match, pattern))
        {
            GTEST_COUT << "Proof: " << line << std::endl;
            found = true;
            break;
        }
    }
    log_file_stream.close();
    return found;
}
