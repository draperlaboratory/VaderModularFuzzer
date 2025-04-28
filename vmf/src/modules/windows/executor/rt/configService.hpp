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
#include <memory>
#include <string>
#include <vector>

/// @brief Main service interface for resolving configuration items to values
/// @details
/// The use of this config service is by the run time context is to share the active VMF
/// configuration via reading the composed configuration from the active 
/// \<output\>/config[#].yaml.
///
/// The obvious question is how does this config interface abstraction differ from
/// the VMF config manager. The principal difference is that this does not couple to a 
/// module concept. 
/// The second is that there is no composition semantics w.r.t the special mappings
/// `vmfVariables` or `vmfClassSet`. 
///
class ConfigService {
   private:
    struct Impl;
    std::unique_ptr<Impl> _impl;

   public:
    ConfigService(void);
    ~ConfigService();
    /// @brief Interpret and add to the configuration state the contents of the
    /// given YAML file.
    /// @param uri YAML format configuration items.
    void addSource(const char *uri);

    /// @brief Interpret and add to the configuration state the contents of the
    /// literal YAML string.
    /// @param data YAML data 
    /// @param length YAML data length
    void addSource(const char *data, size_t length);

    /**
     * @brief  Set context.name = value
     *
     * Will accept a context as a '.' separated list of maps and create the maps to support 
     * the final assignment.
     * @param context a map name 
     * @param name the key name to set
     * @param value the value to assign to key.name
     * @throws on catastropic error expanding variables in value
     */
    void assign(const std::string &context, const std::string &name, const std::string &value );

    /// @brief Resolve a "dotted" key path and key name to a string value.
    /// @param context "dotted" key path
    /// @param name key name under context path
    /// @param defValue default value to return if context.name doesn't exist
    /// @return string value of context.name
    std::string resolve(const std::string &context, const std::string &name,
                        std::string defValue);

    /// @brief Resolve a "dotted" key path and key name to a bool value.
    /// @param context "dotted" key path
    /// @param name key name under context path
    /// @param defValue default value to return if context.name doesn't exist
    /// @return string value of context.name
    bool resolve(const std::string &context, const std::string &name,
                        bool defValue);

    /// @brief Resolve a "dotted" key path and key name to a size (unsigned int) value.
    /// @param context "dotted" key path
    /// @param name key name under context path
    /// @param defValue default value to return if context.name doesn't exist
    /// @return unsigned integer value of context.name
    size_t resolve(const std::string &context, const std::string &name,
                        size_t defValue);

    /// @brief Resolve a "dotted" key path and key name to a list of string
    /// values.
    /// @param context "dotted" key path
    /// @param name key name under context path
    /// @param defValue default value to return if context.name doesn't exist
    /// @return list of string values for context.name
    std::vector<std::string> resolve(const std::string &context,
                                     const std::string &name,
                                     std::vector<std::string> defValue);

    /// @brief dump current YAML to console for diagnostics
    void dump(void);
};
