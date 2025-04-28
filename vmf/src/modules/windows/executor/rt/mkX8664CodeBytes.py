# =============================================================================
# Vader Modular Fuzzer (VMF)
# Copyright (c) 2021-2025 The Charles Stark Draper Laboratory, Inc.
# <vmf@draper.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 (only) as 
# published by the Free Software Foundation.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#  
# @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
# ===========================================================================*/
## @package mkX8664CodeBytes
# This script generates a C++ function that returns a copy of an assembly code block where literal value references 
# are replaced with the values of a set of arguments. 
# 
# This is like a runtime loader with fixups or relocs. 
# 
from keystone import *
import re
from collections import defaultdict

#
# A literal assembly fragment where dynamic operands are replaced by values given by a "loader" function.
# A literal operand can support 1,2,4,8 byte widths by being referenced as '#name:byte width'
# Literal references (with '#') must not appear in comments
# Literal must always be a SRC operand. 
# 
# For ease of parsing and managing, we only allow a single instruction per line.
# This should not be an undue burdon for asm authors
# This block must not assume any specific ABI and preserve all registers/flags
# 

## 
# @brief AFL++ 16bit map ASM fragment
# Accept a uint64_t prev_pc, uint16_t id, uint64_t map, uint16_t id2
# Implements the AFL++ style coverage collection as:
#   saturated_add8bit(1, map[*prev_pc ^ id % 65536]) 
#   *prev_pc = id2;
block_edge_16bit = """// Store the context
            ; push rax
            ; lahf
            ; push rax
            ; push rbx
            ; push rcx

            // Load the previous_pc in RCX
            ; mov rcx, QWORD PTR #prev_pc:8
            ; movzx rax, WORD PTR [rcx]
            // Calculate the edge id in RAX 
            ; xor rbx,rbx // Clear rbx, no form of movzx with immediate.
            ; mov bx, #id:2
            ; xor ax, bx

            // Load the map byte address in RBX
            ; mov rbx, QWORD PTR #map:8
            ; add rbx, rax

            // Update the map byte count
            ; mov al, BYTE PTR [rbx]
            ; add al,0x1
            ; adc al,0x0
            ; mov BYTE PTR [rbx],al

            // Update the previous_pc value
            ; mov bx, #id2:2
            ; mov WORD PTR [rcx], bx

            // Restore the context
            ; pop rcx
            ; pop rbx
            ; pop rax
            ; sahf
            ; pop rax
            """

def parse_code( code ):
    """ code: A literal assembly fragment where dynamic operands are replaced by values given by a "loader" function.
              A literal operand can support 1,2,4,8 byte widths by being referenced as '#name:byte width'
              A literal must be the SRC operand, and is assumed to be contained in the last {width} bytes of the encoded instruction
              For ease of parsing and managing, we only allow a single instruction per line.
        returns: (bytes, { name: [list of offsets to set values] }, { name: width }  )
    """
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    # recognize the literal references by pattern (no attempt to filter comments is applied to keep this tokenizing simple)
    litp = re.compile( "#([A-z_0-9]+):([0-9]+)" )
    buffer = []
    fixups = defaultdict(list)
    ids = {}
    for line in code.split('\n'):
        lit = re.search( litp, line )
        if lit:
            w = int(lit.group(2))
            name = lit.group(1)
            if name in ids and w != ids[name] :
                raise Exception(f"ID {name} has changed size, this cannot work")
            ids[name] = w
            sub = "01" + "00" * (w - 1) + "h"
            line = re.sub(litp,sub, line) # Put in the assembly a zero literal with appropriate width
        try:
            data,_ = ks.asm(line)
        except KsError as e :
            print(f"Error assembling {line}")
            raise e
        if data:
            buffer.extend(data)
        if lit: # There was a pattern, so record position 
            # We assume the literal value is the last {width} bytes. 
            # This results in the SRC operand restriction. 
            fixups[name].append( len(buffer)-w )
    return buffer, fixups, ids

def gen_function( name, buffer, fixups, ids ) :
    """
    Generate CPP class for a given asm buffer with binding fixups and parameters (ids)
    """
    global func_template
    asmBytes = ",".join([str(i) for i in buffer])
    asmLen = len(buffer)
    param_decl = ",".join( [ f"uint{width*8}_t {id_name}" for id_name,width in ids.items() ])
    id_setter_decl = ";".join( [ f"uint{width*8}_t *{id_name}_set" for id_name,width in ids.items() ])
    stmts = []
    for id,width in ids.items(): 
        for occur in fixups[id]:
            stmts.append( f"{id}_set = reinterpret_cast<uint{width*8}_t *>(here + {occur})")
            stmts.append( f"*{id}_set = {id}")
    id_assign_stmts = ";\n            ".join( stmts )

    with open(f"{name}_asm.hpp",'wt') as out:
        out.write( func_template.format( **locals() ) )

## 
# @brief CPP class templated with bytes and binding data to support 
# generating bound ASM fragment instances.
func_template = """/* =============================================================================
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
 /* 
 * DO NOT EDIT, 
 * 
 * This file is generated by the script mkX8664CodeBytes.py 
 * The 
*/
#include <stdint.h>
#include <cstring>

/** 
 * @brief return ASM code with literal references bound to the variables of getInstance
 *
*/ 
class {name}_asmGen {{
    public:
        /** 
        * @brief size of literal asm byte's abstracted by this class
        */
        static constexpr size_t blockSize = {asmLen};
    protected:
        /** 
        * @brief a parameterized asm block
        */
        static const uint8_t _asmBytes[blockSize];
    public: 
        /** 
        * @brief substitute parameters provided in a copy of the asm bytes
        */
        static void getInstance( uint8_t here[{name}_asmGen::blockSize], {param_decl} ) {{
            {id_setter_decl};
            
            std::memcpy( here, _asmBytes, blockSize );
            {id_assign_stmts};
        }}
}};
const uint8_t {name}_asmGen::_asmBytes[{name}_asmGen::blockSize] = {{ {asmBytes} }};
"""

if __name__ == '__main__' : 
    ## @var buffer
    # the bytes
    ## @var fixups 
    # the offsets of places to patch
    ## @var ids 
    # are the names of parameters
    buffer, fixups, ids = parse_code(block_edge_16bit)    
    gen_function( 'block_edge_map16', buffer, fixups, ids )
