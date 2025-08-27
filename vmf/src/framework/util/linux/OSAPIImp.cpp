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
#include "OSAPIImp.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "VmfUtil.hpp"
#include <dlfcn.h>
#include <filesystem>
#include <libgen.h>         // dirname
#include <unistd.h>         // readlink
#include <linux/limits.h>   // PATH_MAX

using namespace vmf;

OSAPI& OSAPI::instance()
{
    static OSAPIImp singleton;
    return singleton;
}

OSAPIImp::OSAPIImp()
{
    
}

OSAPIImp::~OSAPIImp()
{

}

void* OSAPIImp::openDLL(std::string pathToLibrary)
{
    void* handle = dlopen(pathToLibrary.c_str(), RTLD_LAZY);
    if (!handle)
    {
        std::string msg = "unable to load shared library " + pathToLibrary;
        msg += ": ";
        msg += dlerror();
        LOG_ERROR << msg;
        throw RuntimeException(msg.c_str());
    }

    return handle;
}

void OSAPIImp::closeDLL(void* handle)
{
    dlclose(handle);
}

int OSAPIImp::getOption(int argc, char* argv[], const char* optstring)
{
    return getopt(argc, argv, optstring);
}

std::string OSAPIImp::getOptionArg()
{
    return std::string(optarg);
}

int OSAPIImp::getProcessID()
{
    return ::getpid();
}

std::string OSAPIImp::getHostname()
{
    char buff[255];
    int ok = gethostname(buff, 255);
    if (0 != ok)
    {
        LOG_ERROR << "Hostname not found, error code=" << errno;
        return "UNKNOWN_HOST";
    }
    else
    {
        return std::string(buff);
    }
}

std::string OSAPIImp::getExecutablePath()
{
    char result[PATH_MAX];
    const char *path = nullptr;

    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    if (count > 0) {
        result[count] = 0;
        path = dirname(result);
    }
    std::string val(path);
    return val;

}


bool OSAPIImp::commandLineUnzip(std::string zipFilePath, std::string outputDir)
{
    bool success = false;
    //Example usage:
    // unzip -q ../ZIPAUTOGEN_TEST.zip -d ~/ziptest/out2

    //Create the output directory if it doesn't exist
    if(!VmfUtil::directoryExists(outputDir))
    {
        VmfUtil::createDirectory(outputDir.c_str());
    }

    //Unzip the file
    std::string unzipCmd = "unzip -q " + zipFilePath + " -d " + outputDir;
    if(system(unzipCmd.c_str())==0)
    {
        success = true;
    }
    else
    {
        LOG_ERROR << "Unable to unzip file using command;" << unzipCmd;
    }
    
    return success;
}

bool OSAPIImp::commandLineZip(std::string zipFilePath, std::string inputDir)
{
    bool success = false;
    //Example usage:
    // zip -r -j -q myzip2.zip ~/testing/*

    //Make sure the input directory exists
    if(VmfUtil::directoryExists(inputDir))
    {
        std::string zipCmd = "zip -r -j -q " + zipFilePath + " " + inputDir + "/*";
        if(system(zipCmd.c_str())==0)
        {
            success = true;
        }
        else
        {
            LOG_ERROR << "Unable to unzip file using command;" << zipCmd;
        }
    }
    else
    {
        LOG_ERROR << "Zip input directory not found; " << inputDir;
    }

    return success;
}

void OSAPIImp::setSignalHandlers(sighandler_t handler)
{
    signal(SIGINT, handler);
    signal(SIGTERM, handler);
    signal(SIGHUP, handler);
    signal(SIGQUIT, handler);
}
