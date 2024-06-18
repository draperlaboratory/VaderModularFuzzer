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
#pragma once
#ifndef PLUGINS_HPP
#define PLUGINS_HPP

#include <list>
#include <memory>

namespace vmf
{

/**
 * @brief Supports dynamic loading/unloading of shared libraries.
 * 
 * This is a simple container that isolates platform aspects of loading a shared
 * library at runtime.  The container loads the shared library at construction
 * time, and unloads it when destroyed.
 *
 * Future expansion might include template functions to obtain C++ functions/interfaces
 * by symbol name, although these are not needed by the VMF framework currently.
 */
class SharedLibrary
{
    // handle to the loaded library
    void *handle;

    // library name used for logging purposes
    std::string libraryName;
public:

    /**
     * @brief Construct a new shared library
     * 
     * At construction time we load the requested shared library, and retain a handle to
     * it.  The shared library will be unloaded when the SharedLibrary instance is destroyed.
     * If the shared library cannot be (e.g., null pointer returned from dlopen), a
     * RuntimeException will be thrown.
     * 
     * @param pathToLibrary path to the shared library to be loaded
     */
    SharedLibrary(std::string pathToLibrary);

    /**
     * @brief Destroy the shared library.
     * 
     * Unloads the shared library from memory.
     */
    ~SharedLibrary();
};

/**
 * @brief VMF Application Plugin loader support
 * 
 * Provides a container for holding a set of plugins to a VMF application.  Plugins are collections
 * of modules and/or storage modules that are aggregated into shared libraries and loaded at runtime.
 * A VMF application doesn't link statically to modules, instead loading them as requested.
 *
 * This class supports loading all shared libraries that it finds in a directory.  Additional
 * plugins can be loaded from specific locations.  When the PluginLoader instance is destroyed,
 * any plugins it holds will be unloaded.
 *
 * Plugins will register their modules with the singleton ModuleFactory when they are loaded.
 * 
 */
class PluginLoader {
    std::list<std::shared_ptr<SharedLibrary>> plugins;
public:
    /**
     * @brief Load all plugins from a directory.
     * 
     * This method will scan all files in the given directory, loading any files that
     * have a shared library extension (e.g., ".so" on Linux).  All loaded plugins are
     * place on a list.
     *
     * May throw a RuntimeException if there is an error loading any shared library found
     * when scanning the directory.
     * 
     * @param pluginDirectory Directory to load the plugins from
     */
    void loadAll(std::string pluginDirectory);

    /**
     * @brief Loads a single plugin from a specific location.
     * 
     * Given a specific filename, this method will load the plugin.  A pointer to
     * the shared library will be returned.  The shared library will also be added
     * to the list of plugins this class manages.  The return value is provided against the
     * day that some code wishes to be able to extract specific interfaces from the
     * shared library that is loaded.
     *
     * If there is an error loading the plugin a RuntimeException will be thrown.
     * 
     * @param pluginName path to the plugin to be loaded.
     */
    std::shared_ptr<SharedLibrary> loadSpecific(std::string pluginName);
};

}

#endif

/* Local Variables:  */
/* mode: c++         */
/* End:              */
