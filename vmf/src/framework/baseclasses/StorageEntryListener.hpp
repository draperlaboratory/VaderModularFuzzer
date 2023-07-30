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

#include "StorageEntry.hpp"

namespace vader
{
class StorageEntry; //forward declaration

/**
 * @brief Helper class to notify storage when the primary storage key is updated
 * 
 * Implementations of Storage that need to know when the primary key (or sort by key)
 * is changed, must inherit from this class.  StorageEntry will call the associated
 * listener when the primary key is updated.
 * 
 */
class StorageEntryListener
{
public:
    /**
     * @brief Called by StorageEntry when the primary key is changed
     * 
     * StorageEntry will call this method on the associated StorageEntryListener
     * whenever the primary key value is written.
     * @param entry the entry for which the primary key was updated
     */
    virtual void notifyPrimaryKeyUpdated(StorageEntry* entry) = 0;
};

}