/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
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

#include <dlfcn.h>
#include <filesystem>

#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "Plugins.hpp"

using namespace vader;

SharedLibrary::SharedLibrary(std::string pathToLibrary)
{
    LOG_INFO << "loading shared library " << pathToLibrary << "\n";
    handle = dlopen(pathToLibrary.c_str(), RTLD_LAZY);
    if (!handle)
    {
	std::string msg = "unable to load shared library " + pathToLibrary;
	msg += ": ";
	msg += dlerror();
	LOG_ERROR << msg;
	throw RuntimeException(msg.c_str());
    }
    libraryName = pathToLibrary;
}

SharedLibrary::~SharedLibrary()
{
    LOG_INFO << "unloading shared library " << libraryName << "\n";
    dlclose(handle);
}

void PluginLoader::loadAll(std::string pluginDirectory)
{
    namespace stdfs = std::filesystem;

    for (auto f: stdfs::directory_iterator(pluginDirectory))
    {
	if (stdfs::is_regular_file(f))
	{
	    auto ext = f.path().extension();
	    if (ext == ".so")
	    {
		loadSpecific(f.path());
	    }
	}
    }
}

std::shared_ptr<SharedLibrary> PluginLoader::loadSpecific(std::string pluginName)
{
    std::shared_ptr<SharedLibrary> res = std::make_shared<SharedLibrary>(pluginName);
    plugins.push_back(res);
    return res;
}
