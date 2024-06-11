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

#include "StorageEntry.hpp"

namespace vmf
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
     * whenever the primary key value is written.  This method does not need to be called
     * for metadata or local entries.
     * 
     * @param entry the entry for which the primary key was updated
     */
    virtual void notifyPrimaryKeyUpdated(StorageEntry* entry) = 0;

    /**
     * @brief Called by StorageEntry when a tag is set
     * 
     * StorageEntry will call this method on the associated StorageEntryListener
     * whenever a tag is set on a StorageEntry.  This method must not be called for metadata
     * or local entries.  Metadata may not be tagged at all.  Local entries may be tagged,
     * but the StorageModule should not be notified when they are.
     * 
     * @param entry the entry for which the tag was set
     * @param tagId the handle for the tag
     */
    virtual void notifyTagSet(StorageEntry* entry, int tagId) = 0;

    /**
     * @brief Called by StorageEntry when a tag is removed
     * 
     * StorageEntry will call this method on the associated StorageEntryListener
     * whenever a tag is removed on a StorageEntry.  This method must not be called for metadata
     * or local entries.  Metadata may not be tagged at all.  Local entries may be tagged,
     * but the StorageModule should not be notified when they are.
     * 
     * @param entry the entry for which the tag was removed
     * @param tagId the handle for the tag
     */
    virtual void notifyTagRemoved(StorageEntry* entry, int tagId) = 0;
};

}