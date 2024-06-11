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
#include "SimpleIterator.hpp"

using namespace vmf;
/**
 * @brief Construct a new Simple Iterator object
 * 
 * @param theList the list<StorageEntry*> that this iterator should traverse
 */
SimpleIterator::SimpleIterator(std::list<StorageEntry*>& theList)
{
    elementPointers = &theList;
    pointerIterator = (*elementPointers).begin();
}

StorageEntry* SimpleIterator::getNext()
{
    StorageEntry* theEntry = *pointerIterator;
    pointerIterator++; //increment the iterator to be pointed at the next element
    return theEntry;
}

bool SimpleIterator::hasNext()
{
    return(pointerIterator != (*elementPointers).end());
}


int SimpleIterator::getSize()
{
    return (*elementPointers).size();
}

StorageEntry* SimpleIterator::setIndexTo(int index)
{
     pointerIterator = (*elementPointers).begin();
     std::advance(pointerIterator, index);
     StorageEntry* theEntry = *pointerIterator;
     return theEntry;
}

void SimpleIterator::resetIndex()
{
    pointerIterator = (*elementPointers).begin();
}
