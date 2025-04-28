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
#define min min
#include <windows.h>
#include <psapi.h>

#include "vmfFrida_instrumenter.hpp"

#define _GNU_SOURCE
#include <fcntl.h>
#include <frida-gum.h>

#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <ostream>

/* dbghelp provided with frida-gum is missing a close on the cplusplus guard. */
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include "block_edge_map16_asm.hpp"
#pragma warning(disable : 4984) // Disable C++17 extension warning */

#include "xxHash.hpp"

extern void vmfFrida_exit(int);

static bool _debug = false;

static bool _stalking = false; /* Test first, then see if we can replace the hook with a don't stalk */

static GumStalker *_stalker = NULL;
static GumStalkerTransformer *_transformer = NULL;

/* Coverage filtering */
typedef std::pair<uint64_t, uint64_t> RangeInterval;

/**
 * @brief Metadata collected for each block observed by 'stalker'
 */
struct Block {
    uint32_t regionID;      /**< ID of range containing block */
    uint64_t offset;        /**< Offset of block within containing range */
    uint32_t size;          /**< Size of block in bytes */
    uint16_t hashIndex;     /**< Map hash index of block (if instrumented) */
    uint32_t firstTest;     /**< Test index executing when block was first executed */
    int instrumented;       /**< Block is instrumented (hash not valid when 0) */
    std::string dbgName;    /**< DBG Symbol associated with block address, if available */
    uint64_t dbgNameOffset; /**< DBG offset of block address within Symbol, if available  */
};

std::vector<Block> _blocks;

/**
 * @brief A non-overlapping address interval in the instrumented process space.
 *
 */
struct Range
{
    static int _instanceCount; /**< Used to generate _id */
    RangeInterval _range;      /**< Address range as 64bit interval [) */
    std::string _name;         /**< Name of section (DLL/EXE name) */
    uint32_t _id;              /**< A unique id, hash of name */
    size_t _idIndex;           /**< A unique id, currently the order of enumeration prodived by underlying implementation */
    bool _instrument;          /**< Instrument executing blocks within this range */

    /**
     * @brief Provide type cast to allow Range to used in place of a RangeInterval
     */
    operator RangeInterval() { return _range; }

    /**
     * @brief construct Range over the given address range
     */
    Range(uint64_t bottom, uint64_t top, std::string name, bool instrument) : _range(bottom, top),
                                                                              _name(name),
                                                                              _instrument(instrument) { 
                                                                                xxh::hash_t<32> hashID = xxh::xxhash<32>((void *)name.c_str(), name.length());
                                                                                _id = hashID;
                                                                                _idIndex = _instanceCount++; 
                                                                            }

    /**
     * @brief construct Range with a single address (used to query)
     */
    Range(uint64_t value) : _range(value, value), _id(-1), _instrument(false) {}
};

// specialized transparent functor for operator<
namespace std
{ // Doxygen parsing goof, cannot handle namespace qualifier stuct std::less

    /**
     * @brief specialize less<RangeInterval> to provide total ordering of non-overlapping RangeIntervals
     */
    template <>
    struct less<RangeInterval>
    {
        /**
         * @brief return lhv < rhv
         *
         * @param lhv
         * @param rhv
         * @return true
         * @return false
         */
        bool operator()(const RangeInterval &lhv, const RangeInterval &rhv) const
        {
            return lhv.first < rhv.first && lhv.second < rhv.first;
        }
    };

} // Close namespace for doxygen goof.

int Range::_instanceCount = 0;

HANDLE _hOurProc;

static std::map<RangeInterval, Range> _inScopeMap;
static std::set<std::string> _instrumentDLLs;

uint64_t *_prev_pc_p;
uint8_t *_trace_bits;
const size_t *_nTest;

static void stalker_instrument_block(GumStalkerIterator *iterator,
                                     GumStalkerOutput *output,
                                     gpointer user_data)
{
    const cs_insn *instr;
    gboolean begin = TRUE;
    gboolean excluded = TRUE;
    uint32_t count = 0;
    uint16_t id = 0;
    uint16_t id1 = 0;
    auto range = _inScopeMap.end();

    GumAddress start, dest;
    GumAddress end;
    uint8_t *codeToInsert = (uint8_t *)alloca(block_edge_map16_asmGen::blockSize);

    if (gum_stalker_iterator_next(iterator, &instr))
    {
        start = instr->address;
        dest = (GumAddress)gum_x86_writer_cur(output->writer.x86);

        range = _inScopeMap.find(Range(start));

        if (range != _inScopeMap.end())
        {
            if (range->second._instrument)
            {
                uint32_t value[2] = {(uint32_t)(start - range->second._range.first), (uint32_t)range->second._id};

                xxh::hash_t<64> hash = xxh::xxhash<64>((void *)value, sizeof(value));
                id = (uint16_t)hash;
                id1 = (uint16_t)(hash >> 1);
                excluded = FALSE;
                
                block_edge_map16_asmGen::getInstance(codeToInsert, (uintptr_t)_prev_pc_p, id, (uint64_t)_trace_bits, id1);
                gum_x86_writer_put_bytes(output->writer.x86, codeToInsert, block_edge_map16_asmGen::blockSize);
            }
        }
        else
        {
            /* An address is being hit, without knowing where it came from: */
        }
        do
        {
            count++;
            end = instr->address;
            gum_stalker_iterator_keep(iterator);
        } while (gum_stalker_iterator_next(iterator, &instr));
    }

    if (_debug)
    {
        PSYMBOL_INFO si = (PSYMBOL_INFO)alloca(sizeof(SYMBOL_INFO) + 2048);
        si->Name[0] = '\0';
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen = 2048 - sizeof(SYMBOL_INFO);

        if (SymFromAddr(_hOurProc, start, 0, si))
        {
        }
        else
        {
            si->Name[0] = '\0';
        }

        Block newBlock = {
            range != _inScopeMap.end() ? range->second._id : (uint32_t)-1,
            range != _inScopeMap.end() ? start - range->second._range.first : start,
            count,
            id,
            (uint32_t)*_nTest,
            !excluded,
            si->Name,
            si->Name[0] != '\0' ? start - si->Address : 0};
        _blocks.emplace_back(newBlock);
    }
}

/* Taking from libAFL the notion that exclusion causes issues with exception frame unwinding,
        so rather than exclude from stalker, apply specific inclusion in instrumentation transformer.

        ref LibAFL:
        Disable `stalker.exclude()` if `true`
        It's better to disable this on Windows or your harness uses c++ exception handling
        See <https://github.com/AFLplusplus/LibAFL/issues/830>
        */
static gboolean stalker_exclude_things(const GumRangeDetails *details, gpointer user_data)
{
    gchar *name = NULL;

    if (details->file == NULL)
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T ret;

        ret = VirtualQuery((LPVOID)details->range->base_address, &mbi, sizeof(mbi));
        if (mbi.Type & MEM_MAPPED)
        {
            printf("%p Address is Mapped\n", (void *)details->range->base_address);
        }
        else if (mbi.Type & MEM_IMAGE)
        {
            char nameBuffer[1024];
            GetMappedFileNameA(GetCurrentProcess(), (LPVOID)details->range->base_address, nameBuffer, sizeof(nameBuffer) - 1);
            name = g_path_get_basename(nameBuffer);
        }
        else if (mbi.Type & MEM_PRIVATE)
        {
            printf("%p Address is Private\n", (void *)details->range->base_address);
        }
    }
    else
    {
        name = g_path_get_basename(details->file->path);
    }

    if (name != NULL)
    {
        gboolean found;

        /* List of excluded fragments, probably something that should be configurable */
        /* Exclusion can lead lead to inconsistencies with exceptions and create missed code relevant to the
        test coverage: see https://github.com/AFLplusplus/LibAFL/issues/830#issuecomment-1303147804

        Another issue is that exclusion does not apply to IAT DLL/linkage because these are indirect call's.
        Linux/Frida has some plt like handling here:
        https://github.com/frida/frida-gum/blob/3e755c907a4a6308dee7f202151238d05cc94930/gum/backend-x86/gumstalker-x86.c#L2465

        Something similiar for windows should be integrated and upstreamed.
        */
        found = (g_strcmp0(name, "vmf_frida_rtembed.dll") == 0) ||
                (g_strcmp0(name, "ucrtbase.dll") == 0) ||
                (g_strcmp0(name, "ucrtbased.dll") == 0) ||
                (g_strcmp0(name, "vcruntime140d.dll") == 0) ||
                (g_strcmp0(name, "vcruntime140_ld.dll") == 0) ||
                (g_strcmp0(name, "vcruntime140.dll") == 0) ||
                (g_strcmp0(name, "vcruntime140_l.dll") == 0) ||
                (g_strcmp0(name, "msvcp140d.dll") == 0) ||
                (g_strcmp0(name, "msvcp140.dll") == 0) ||
                (g_strcmp0(name, "ntdll.dll") == 0) ||
                (g_strcmp0(name, "msvcrt.dll") == 0);
        if (found)
        {
            // exclude something we found....
            gum_stalker_exclude(_stalker, details->range);
            Range el(details->range->base_address,
                     details->range->base_address + details->range->size, name, false);
            _inScopeMap.emplace(el._range, el);
        }
        else
        {
            Range el(details->range->base_address,
                     details->range->base_address + details->range->size, name, true);
            _inScopeMap.emplace(el._range, el);
        }

        if (_instrumentDLLs.find(name) != _instrumentDLLs.end())
        {
            Range el(details->range->base_address,
                     details->range->base_address + details->range->size, name, true);
            _inScopeMap.emplace(el._range, el);
        }
        g_free(name);
    }

    // Since we are looking for multiple things, continue.
    return TRUE;
}

VMFFridaInstrumenter::VMFFridaInstrumenter(uint8_t *trace_bits, uint64_t *prev_pc, const size_t *nTest, std::set<std::string> &instrumentNames, bool debug)
{
    _trace_bits = trace_bits;
    _prev_pc_p = prev_pc;
    _nTest = nTest;
    _debug = debug;

    _hOurProc = GetCurrentProcess();

    gum_init_embedded();

    /* Not really effective for windows, but maybe in the future this will be fixed */
    gum_stalker_activate_experimental_unwind_support();

/* In the future we will neeed config entry support for ic_entries and adjacent blocks */
#if defined(__x86_64__) || defined(__i386__)
    stalker = g_object_new(GUM_TYPE_STALKER, "ic-entries", stalker_ic_entries,
                            "adjacent-blocks", stalker_adjacent_blocks, NULL);
#elif defined(__aarch64__)
    stalker = g_object_new(GUM_TYPE_STALKER, "ic-entries", stalker_ic_entries, NULL);
#else
    _stalker = gum_stalker_new();
#endif

    if (_stalker == NULL)
    {
        g_warning("Failed to initialize stalker\n");
        vmfFrida_exit(__LINE__);
    }

    _transformer = gum_stalker_transformer_make_from_callback(stalker_instrument_block, NULL, NULL);
    if (_transformer == NULL)
    {
        g_warning("Failed to initialize stalker\n");
        vmfFrida_exit(__LINE__);
    }

    /* Trust threshold on self-modifying code. */
    gum_stalker_set_trust_threshold(_stalker, 0);

    /* *NEVER* stalk the stalker, only bad things will ever come of this! */
    gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, stalker_exclude_things, NULL);

    /* No reason to use GUM dbghelp wrapper */
    SymInitialize(GetCurrentProcess(), NULL, TRUE);

}

void VMFFridaInstrumenter::Enable( void )
{
    gum_stalker_follow_me(_stalker, _transformer, NULL);
    gum_stalker_deactivate(_stalker);
}

void VMFFridaInstrumenter::Activate(const void *target)
{
    gum_stalker_activate(_stalker, target);
}

void VMFFridaInstrumenter::Deactivate( void )
{
    gum_stalker_deactivate(_stalker);
}

void VMFFridaInstrumenter::Disable( void )
{
    gum_stalker_unfollow_me(_stalker);
}

void VMFFridaInstrumenter::DumpMeta(std::ostream &mapMetaFile)
{
    bool first = true;
    mapMetaFile << "{ \"ranges\": [ ";
    for (auto &el : _inScopeMap)
    {
        if (!first)
        {
            mapMetaFile << ",{";
        }
        else
        {
            mapMetaFile << "{";
            first = false;
        }
        mapMetaFile << "\"name\": \"" << el.second._name << "\", \"regionID\": " << el.second._id << "}";
        /*", \"base\": " << el.second._range.first <<
        ", \"end\": " << el.second._range.second << */
    }
    mapMetaFile << "],";
    /* Blocks */
    mapMetaFile << "\n\"blocks\": [ ";
    first = true;
    for (auto el : _blocks)
    {
        if (!first)
        {
            mapMetaFile << ",{";
        }
        else
        {
            mapMetaFile << "{";
            first = false;
        }
        mapMetaFile << " \"regionID\": " << el.regionID << ", \"offset\": " << el.offset << ", \"size\": " << el.size << ", \"instrumented\": " << el.instrumented << ", \"symbol\": \"" << el.dbgName << "\"" << ", \"symbolOffset\": " << el.dbgNameOffset << ", \"hashIndex\": " << el.hashIndex << ", \"firstTest\": " << el.firstTest << "}";
    }
    mapMetaFile << "] }";
}
