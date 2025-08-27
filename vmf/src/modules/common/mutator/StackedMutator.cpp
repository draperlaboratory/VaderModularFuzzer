/* =======================
======================================================
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
#include "RuntimeException.hpp"
#include "StackedMutator.hpp"
#include "MutatorSelector.hpp"
#include "Logging.hpp"
#include "math.h"
#include "float.h"
#include <numeric>

using namespace vmf;

/*
  This will register the mutator module with the VMF module factory, making
  it available for use via VMF configuration files.
 */
#include "ModuleFactory.hpp"
REGISTER_MODULE(StackedMutator);

/**
 * @brief Builder method to support the ModuleFactory
 * Constructs an instance of this class
 * @return Module* 
 */
Module* StackedMutator::build(std::string name)
{
    return new StackedMutator(name);
}

/**
 * @brief Initialization method
 * Reads in all configuration options for this class
 * 
 * @param config 
 */
void StackedMutator::init(ConfigInterface& config)
{
    // Call upon the config option to read any config parameters, such as
    // Assume a stacksize equal the number of mutators provided 
    std::vector<Module*> mutators_config = config.getSubModules(getModuleName());
    _StackedMutator_num_mutators = static_cast<int>(mutators_config.size());
    MutatorModule *mutator = nullptr;
    for (int i = 0; i < _StackedMutator_num_mutators; i++)
    {
        if ((mutator = static_cast<MutatorModule*>(mutators_config[i])) != nullptr)
        {
            _StackedMutator_mutators.push_back(mutator);
        }
    }


    if (_StackedMutator_num_mutators == 0)
        throw RuntimeException("Cannot declare a mutation stack with no mutators",  RuntimeException::USAGE_ERROR);
    
    _StackedMutator_max_size = config.getIntParam(getModuleName(), "stackSize", _StackedMutator_num_mutators);
    if (_StackedMutator_max_size == 0)
        throw RuntimeException("Cannot declare a zero-length mutation stack", RuntimeException::USAGE_ERROR);
    
    // assume fixed stack size by default
    _StackedMutator_randomize_stack_size = config.getBoolParam(getModuleName(), "randomStackSize", false);

    _StackedMutator_user_choice = config.getStringParam(getModuleName(), "mutatorSelector", "staticMutatorSelector");
    
    // Initial mutator selector object, which will manage the list of mutators
    initMutatorSelector(
        config,
        _StackedMutator_mutators
    );

    // Initialize utilities
    random = VmfRand::getInstance();

    if (config.isParam(_StackedMutator_user_choice, "mutatorSelectionDistribution"))
        LOG_INFO << "Configuration " << getModuleName() << ":" << \
                " mutators=" << _StackedMutator_mutators << \
                " stackSize=" << _StackedMutator_max_size << \
                " randomStackSize=" << _StackedMutator_randomize_stack_size << \
                " mutatorSelector=" << _StackedMutator_selection_algorithm->getModuleName() << \
                " mutatorSelectionDistribution=" << config.getFloatVectorParam(_StackedMutator_user_choice, "mutatorSelectionDistribution");
    else
        LOG_INFO << "Configuration " << getModuleName() << ":" << \
            " mutators=" << _StackedMutator_mutators << \
            " stackSize=" << _StackedMutator_max_size << \
            " randomStackSize=" << _StackedMutator_randomize_stack_size << \
            " mutatorSelector=" << _StackedMutator_selection_algorithm->getModuleName();
        
}


void StackedMutator::initMutatorSelector(
    ConfigInterface& config,
    std::vector<MutatorModule*> mutators)
{
    if (_StackedMutator_user_choice == "staticMutatorSelector")
        _StackedMutator_selection_algorithm = new StaticSelector();
    else if (_StackedMutator_user_choice == "uniformMutatorSelector")
        _StackedMutator_selection_algorithm = new UniformSelector();
    else if (_StackedMutator_user_choice == "WeightedRandomSelector")
        _StackedMutator_selection_algorithm = new WeightedRandomSelector();
    else
    {
        LOG_ERROR << "Unrecognied `mutatorSelector` value: '" << _StackedMutator_user_choice << "'";
        throw RuntimeException("Unrecognied `mutatorSelector` value", RuntimeException::USAGE_ERROR);
    }
    
    LOG_DEBUG << "Initializaing `mutatorSelector` value: '" << _StackedMutator_user_choice << "' for " << getModuleName();
    _StackedMutator_selection_algorithm->init(config, getModuleName(), mutators, nullptr);
}


/**
 * @brief Construct a new StackedMutator::StackedMutator object
 * 
 * @param name name of instance 
 */
StackedMutator::StackedMutator(std::string name) :
    MutatorModule(name),
    _StackedMutator_selection_algorithm(nullptr),
    _StackedMutator_user_choice("")
{
}

/**
 * @brief Destroy the StackedMutator::StackedMutator object
 */
StackedMutator::~StackedMutator()
{
    if (_StackedMutator_selection_algorithm != nullptr)
        delete _StackedMutator_selection_algorithm;
    // deletion of mutators must happen in the module that loads the submutators 
    // e.g. the unit test in order to prevent double free that causes the UT exe
    // to throw heap corruption exceptions when built for windows
    _StackedMutator_mutators.clear();
    _StackedMutator_stack.clear();
}

/**
 * @brief Registers storage needs
 * 
 * @param registry 
 */
void StackedMutator::registerStorageNeeds(StorageRegistry& registry)
{
}

/**
 * @brief Creates a new test case by mutating the base entry
 * 
 * Creates a new StorageEntry containing a modified test case buffer. 
 * 
 * @param storage reference to storage
 * @param baseEntry the base entry to use for mutation
 * @param newEntry the test case to write to
 * @param testCaseKey the field to write to in the new entry
 * @throws RuntimeException if baseEntry has an empty test case buffer.
 */
void StackedMutator::mutateTestCase(StorageModule& storage, StorageEntry* baseEntry, StorageEntry* newEntry, int testCaseKey)
{
    int inputSize = baseEntry->getBufferSize(testCaseKey);

    if (inputSize <= 0) 
    {
	    throw RuntimeException("StackedMutator mutate called with zero sized buffer",
	          RuntimeException::USAGE_ERROR);
    }

    // The stack of mutated test cases.  Will last as long as the current fuzzing cycle
    std::vector<StorageEntry*> temps = {baseEntry};

    // Generate mutation stack
    if ((_StackedMutator_num_mutators == _StackedMutator_max_size) && \
        ((_StackedMutator_user_choice == "staticMutatorSelector")) && \
        (_StackedMutator_randomize_stack_size == false)
    )
        _StackedMutator_stack = _StackedMutator_mutators;
    else
        _StackedMutator_stack = generateMutatorStack();

    // Apply stack
    StorageEntry* new_testcase = applyStack(_StackedMutator_stack, temps, storage, testCaseKey);

    //Allocate the new test case buffer (here we go ahead and also copy what was in the baseEntry)
    int outputSize = new_testcase->getBufferSize(testCaseKey);
    char* outputBuffer = newEntry->allocateBuffer(testCaseKey, outputSize);
    memcpy(outputBuffer, new_testcase->getBufferPointer(testCaseKey), outputSize);
}

std::string StackedMutator::getStackAsString(std::vector<MutatorModule*> stack)
{
    std::ostringstream ret;
    size_t stack_size = stack.size();
    for (size_t i = 0; i < stack_size - 1; i++)
    {
        ret << stack[i]->getModuleName() << ", ";
    }
    ret << stack[stack_size - 1]->getModuleName();
    return ret.str();
}

StorageEntry* StackedMutator::applyStack(std::vector<MutatorModule*> stack, std::vector<StorageEntry*> &temps, vmf::StorageModule &storage, int testCaseKey)
{
    for (auto *m : stack)
    {
        mutateLayer(storage, m, temps, testCaseKey);
    }
    return temps.back();
}

/**
 * @brief Creates a new mutation stack
 * 
 * Return a stack of mutators subject to configuration user configuration
 */
std::vector<MutatorModule*> StackedMutator::generateMutatorStack()
{
    size_t stack_size = _StackedMutator_max_size;
    if (_StackedMutator_randomize_stack_size)
    {
        stack_size = static_cast<size_t>(random->randBelowExcept(_StackedMutator_max_size + 1, 0));
    }

    MutatorModule* mutator = nullptr;
    std::vector<MutatorModule*> mutation_stack = {};
    std::map<MutatorModule*, int> apps;
    bool abort = false;

    // initialize the mutator selector
    _StackedMutator_selection_algorithm->startSelect();

    // Generate the stack
    while ((mutation_stack.size() < stack_size) && (abort == false))
    {
        mutator = _StackedMutator_selection_algorithm->selectMutator();
        mutation_stack.push_back(mutator);
    }

    // clear any mutator selector state
    _StackedMutator_selection_algorithm->endSelect();

    return mutation_stack;
}

/**
 * @brief Creates a new mutation layer in the mutation stack by mutating the given base
 * 
 * Creates single extension in the mutation stack
 * 
 * @param storage reference to storage
 * @param m the mutator to use for the current layer
 * @param temps the vector holding the current mutation chain
 * @param testCaseKey the field to write to in the new entry
 */
inline void StackedMutator::mutateLayer(vmf::StorageModule &storage, vmf::MutatorModule *m, std::vector<vmf::StorageEntry *> &temps, int testCaseKey)
{
    StorageEntry *tmpBuff = storage.createLocalEntry();
    m->mutateTestCase(storage, temps.back(), tmpBuff, testCaseKey);
    temps.push_back(tmpBuff);
}



std::vector<MutatorModule*> StackedMutator::getStack(void)
{
    return _StackedMutator_stack;
}
