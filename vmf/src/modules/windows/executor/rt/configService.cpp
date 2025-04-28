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
#include "configService.hpp"

#include <fstream>
#include <iterator>
#include <map>

#include <filesystem>

#ifndef YAML_CPP_STATIC_DEFINE
#define YAML_CPP_STATIC_DEFINE
#endif

#include "yaml-cpp/yaml.h"


/// @brief Internal implementation class for Configuration store
struct ConfigService::Impl {
    /**
     * @brief root node of current config state
     * 
     */
    YAML::Node _root;

    /**
     * @brief Construct a new Impl object
     * 
     */
    Impl() : _root(YAML::NodeType::Null){};

    /**
     * @brief Helper method to check or create a dotted path of map's
     * 
     * Will return the final map of a dotted path, creating intermediates if asked to or 
     * returning an empty node if path must exist. 
     * 
     * @param context - string containing dotted path
     * @param mustExist - returns not defined if path doesn't exist, else creates path
     * @return either the final map of the path or invalid node if not found and not requested to 
     * create intermediates. 
     */
    YAML::Node findPath( const std::string &context, bool mustExist=true ) {
        YAML::Node node(_root);
        std::stringstream contextStream(context);
        std::string item;
        while (getline(contextStream, item, '.')) {
            if ( !node[item] ) {
                if ( mustExist ) {
                    return node;                    
                }
                node[item] = YAML::Node(YAML::NodeType::Map);
                node.reset(node[item]);
            } else {
                node.reset(node[item]);
            }
        }
        return node;
    }

    /**
     * @brief Lookup at map key "name" under a dotted path of keys 
     * 
     * We do not allow command substitution (too dangerous) and will throw 
     * @param context a dot concatenated path of key values providing the container map of name
     * @param name the key name for the value to return
     * @param defValue the value to return if name or any component of path not found.
     * @return either a copy of defValue or the value
     * @throws on catastropic error expanding variables in value
     */
    template <typename T>
    T resolve(const std::string &context, const std::string &name, T defValue) {
        std::string item;
        YAML::Node el;

        el.reset(findPath( context ));
        if (!el.IsDefined()) {
            return defValue;
        }

        auto val = el[name];
        if (val.IsDefined()) {
            return val.IsDefined()? val.as<T>() : defValue;
        }
        return defValue;
    }

    /**
     * @brief Set context.name = value
     *
     * Will accept a context as a '.' separated list of maps and create the maps to support 
     * the final assignment.
     *
     * @param context a map name 
     * @param name the key name to set
     * @param value the value to assign to key.name
     * @throws on catastropic error expanding variables in value
     */
    template <typename T>
    void assign(const std::string &context, const std::string &name, T &value) {
        std::string item;
        YAML::Node node(findPath( context, false ) );
        node[name] = value;
    }

    /**
     * @brief Add the content between iterators provided
     *
     */
    template <typename I>
    void addSource(I begin, I end) {
        std::string yamlSource(begin, end);
        auto node = YAML::Load(yamlSource.data());

        switch (_root.Type()) {
            case YAML::NodeType::Null:
                _root = YAML::Node(YAML::NodeType::Map);
                /* Fall through to catch var filtering */                
            case YAML::NodeType::Map:
                for (const auto &keys : node) {
                    std::string key = keys.first.as<std::string>();
                    _root[key] = keys.second; // node[key];
                }
                break;
            case YAML::NodeType::Sequence:
                _root.push_back(node);
                break;
            default:
                throw std::runtime_error("Root is scalar type syntax error. ");
        }
    }

    /** @brief Dump the current config space for testing */
    void dump() {  }
};

ConfigService::ConfigService() : _impl{std::make_unique<Impl>()} {}

ConfigService::~ConfigService() = default;

void ConfigService::dump(void) { _impl->dump(); }

// Explicit instantiation require for all library usages.
void ConfigService::assign(const std::string &context,
                                   const std::string &name,
                                   const std::string &value) {
    _impl->assign(context, name, value);
}

// Explicit instantiation require for all library usages.
std::string ConfigService::resolve(const std::string &context,
                                   const std::string &name,
                                   std::string defValue) {
    return _impl->resolve(context, name, defValue);
}

// Explicit instantiation require for all library usages.
bool ConfigService::resolve(const std::string &context,
                                   const std::string &name,
                                   bool defValue) {
    return _impl->resolve(context, name, defValue);
}

// Explicit instantiation require for all library usages.
size_t ConfigService::resolve(const std::string &context,
                                   const std::string &name,
                                   size_t defValue) {
    return _impl->resolve(context, name, defValue);
}

std::vector<std::string> ConfigService::resolve(
    const std::string &context, const std::string &name,
    std::vector<std::string> defValue) {
    return _impl->resolve(context, name, defValue);
}

void ConfigService::addSource(const char *path) {
    std::ifstream infile(path, std::ios::binary);
    if (infile.fail()) {
        return; 
    }

    return _impl->addSource(std::istreambuf_iterator<char>(infile),
                            std::istreambuf_iterator<char>());
}

void ConfigService::addSource(const char *data, size_t length) {
   return _impl->addSource(data, (const char *)(data + length) );
}