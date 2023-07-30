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
#pragma once

#include <iostream>
#include <vector>
#include <algorithm>

namespace vader
{
/**
 * @brief This class is used to configure which fields and tags will be maintained in storage.
 *
 */
class StorageRegistry
{
public:

    ///The data types maintained by storage
    enum storageTypes
    {
        INT,
        FLOAT,
        BUFFER //Note: Storage cannot be sorted by a BUFFER type
    };

    static storageTypes stringToStorageType(std::string type);

    ///The types of access that users using storage could have for fields
    enum accessType
    {
        READ_ONLY, ///Reading the field only
        WRITE_ONLY, ///Writing the field only
        READ_WRITE ///Both reading and writing
    };

    ///The order by which the sort by key should be sorted
    enum sortOrder
    {
        ASCENDING,
        DESCENDING
    };

    static sortOrder stringToSortOrder(std::string type);

    StorageRegistry();
    StorageRegistry(std::string sortByKey, storageTypes keyType, sortOrder order);
    ~StorageRegistry();
    bool validateRegistration();
    int registerKey(std::string keyName, storageTypes type, accessType access);
    int registerTag(std::string tagName, accessType access);
    void registerForAllTags(accessType access);
    std::vector<std::string> getTagNames();
    std::vector<int> getTagHandles();
    int getNumKeys(storageTypes type);
    int getNumTags();
    int getSortByKey();
    storageTypes getSortByType();
    sortOrder getSortByOrder();

private:

    struct registryInfo
    {
        std::string name;
        bool isRead;
        bool isWritten;
    };

    int addIfNotPresent(std::vector<registryInfo>& keyList, std::string keyName, accessType access);
    bool validateList(std::vector<registryInfo>& keyList, std::string listName);

    std::vector<registryInfo> tagNames;
    std::vector<registryInfo> intKeys;
    std::vector<registryInfo> floatKeys;
    std::vector<registryInfo> bufferKeys;

    int sortByKeyHandle;
    storageTypes sortByType;
    sortOrder sortByOrder;

    bool readAllTags;
    bool writeAllTags;

};
}