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
#pragma once


#include "StorageEntry.hpp"
#include "Iterator.hpp"
#include <list>

namespace vmf{
/**
 * @brief Implementation of Iterator that works with SimpleStorage implementation
 *
 */
class SimpleIterator : public Iterator
{
public:
    SimpleIterator(std::list<StorageEntry*>& theList);

    virtual StorageEntry* getNext();
    virtual bool hasNext();
    virtual int getSize();
    virtual StorageEntry* setIndexTo(int index);
    virtual void resetIndex();

private:
    std::list<StorageEntry*>* elementPointers;
    std::list<StorageEntry*>::iterator pointerIterator;
};
}