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

#include "Iterator.hpp"


namespace vmf
{
/**
 * @brief Enables iterating through a set of StorageEntries retrieved from the StorageModule
 * Each implementation of StorageModule should provide a companion implementation of Iterator.
 * 
 */
class Iterator
{
public:
    /**
     * @brief Get the Next object
     *
     * @return StorageEntry* The next storage entry
     */
    virtual StorageEntry* getNext() = 0;

    /**
     * @brief Returns true if there are more elements in the iterator
     *
     * @return true if there are more elements
     * @return false otherwise
     */
    virtual bool hasNext() = 0;

    /**
     * @brief Returns the total number of elements in the iterator
     *
     * @return int the size
     */
    virtual int getSize() = 0;

    /**
     * @brief Returns the storage entry at this index
     * This call advances the iterator to this position.  Subsequent calls
     * to getNext and hasNext will be relative to this position.
     *
     * @param index the index to go to (0 to getSize()-1)
     * @return StorageEntry* the storage entry at this index
     */
    virtual StorageEntry* setIndexTo(int index) = 0;

    /**
     * @brief Resets the iterator to the starting position
     * 
     */
    virtual void resetIndex() = 0;

    virtual ~Iterator() {};
};
}