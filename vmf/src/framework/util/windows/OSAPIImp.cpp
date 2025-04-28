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
#include <filesystem>
#include <process.h>
#include <Windows.h>
#include <Winsock2.h>
#include "getopt.h"


using namespace vmf;

OSAPI& OSAPI::instance()
{
    static OSAPIImp singleton;
    return singleton;
}

OSAPIImp::OSAPIImp()
{
    //
    // Initialize Windows Socket API with given VERSION.
    // This is here, and not in UDPMulticastImp, so that WSAStartup is
    // initialized earlier to support things like gethostname (and also to 
    // ensure that it is only called once, UDPMulticastIMP could have more than
    // once instance).
    //
    WSADATA wsaData;
    if (WSAStartup(0x0101, &wsaData))
    {
        perror("WSAStartup");
        return;
    }

}

OSAPIImp::~OSAPIImp()
{
    WSACleanup();
}

void* OSAPIImp::openDLL(std::string pathToLibrary)
{
    std::string stemp = std::string(pathToLibrary.begin(), pathToLibrary.end());
    LPCSTR myDLLfilename = stemp.c_str();
    HINSTANCE hinstLIB = LoadLibrary(myDLLfilename);

    if (hinstLIB == NULL)
    {
        std::string msg = "unable to load shared library " + pathToLibrary;
        msg += ": ";
        auto err = GetLastError();
        msg += (unsigned int) err;
        LOG_ERROR << msg;
        throw RuntimeException(msg.c_str());
    }

    return hinstLIB;
}

void OSAPIImp::closeDLL(void* handle)
{
    FreeLibrary((HMODULE)handle);
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
    return ::_getpid();
}

std::string OSAPIImp::getHostname()
{
    char buff[255];
    int ok = gethostname(buff, 255);
    if (0 != ok)
    {
        int error = WSAGetLastError();
        LOG_ERROR << "Hostname not found, error code=" << error;
        return "UNKNOWN_HOST";
    }
    else
    {
        return std::string(buff);
    }
}

std::string OSAPIImp::getExecutablePath()
{
    TCHAR result[MAX_PATH];
    DWORD length = GetModuleFileName( NULL, result, MAX_PATH );
    std::string fullpath(result);
    std::string noexec = fullpath.substr(0, fullpath.find_last_of("\\/")); //removes the executable name
    return noexec;
    
}

bool OSAPIImp::commandLineUnzip(std::string zipFilePath, std::string outputDir)
{
    bool success = false;
    //Example usage:
    // Tar -m -xf myzip.zip -C outdir

    //Create the output directory if it doesn't exist
    if(!VmfUtil::directoryExists(outputDir))
    {
        VmfUtil::createDirectory(outputDir.c_str());
    }

    //Unzip the file
    std::string unzipCmd = "Tar -m -xf " + zipFilePath + " -C " + outputDir;
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
    // Tar -C inputdir -a -cf myzip.zip *

    //Make sure the input directory exists
    if(VmfUtil::directoryExists(inputDir))
    {
        std::string zipCmd = "Tar -C " + inputDir + " -a -cf " + zipFilePath + " *";
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



