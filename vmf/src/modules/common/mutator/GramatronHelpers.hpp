/* =============================================================================
 * Copyright (c) 2023 Vigilant Cyber Systems
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
#include "GramatronPDA.hpp"
#include "StorageModule.hpp"
#include "VmfUtil.hpp"
#include "Logging.hpp"

namespace vmf
{

/**
 * @brief Common helper functions for Gramatron
 *
 */

Array* gen_input(PDA *pda_s, Array* input, int curr_state);
void createNewTestCasesFromPDA(StorageModule& storage, int testCaseKey, int autRepKey, int num_testcases);
void storeTestCase(StorageEntry* newEntry, Array* input, int testCaseKey, int autRepKey);
}