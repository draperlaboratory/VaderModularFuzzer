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
#include <filesystem>
#include "OSAPI.hpp"
#include "Logging.hpp"
#include "RuntimeException.hpp"
#include "Plugins.hpp"

using namespace vmf;

SharedLibrary::SharedLibrary(std::string pathToLibrary)
{
    LOG_INFO << "loading shared library " << pathToLibrary;
    //An exception will be throw if this load fails
    handle = OSAPI::instance().openDLL(pathToLibrary);
    libraryName = pathToLibrary;
}

SharedLibrary::~SharedLibrary()
{
    LOG_INFO << "unloading shared library " << libraryName;
    OSAPI::instance().closeDLL(handle);
}

void PluginLoader::loadAll(std::string pluginDirectory)
{
    namespace stdfs = std::filesystem;

    for (auto f: stdfs::directory_iterator(pluginDirectory))
    {
	if (stdfs::is_regular_file(f))
	{
	    auto ext = f.path().extension();
	    if ((ext == ".so") || (ext == ".dll"))
	    {
		    loadSpecific(f.path().string());
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
