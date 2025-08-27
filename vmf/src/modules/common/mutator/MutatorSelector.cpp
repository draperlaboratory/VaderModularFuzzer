#include "MutatorModule.hpp"
#include "MutatorSelector.hpp"
#include "ConfigInterface.hpp"
#include "VmfRand.hpp"

#include <cfloat>
#include <string>
using namespace vmf;


// Uniform Probability Distribution

/**
 * @brief Initialize a mutator selection algorithm
 * @param config the ConfigInterface object
 * @param moduleName name of the StackedMutator module
 * @param mutators list of mutators to select from
 * @param initData pointer to arbitrary initialization data
 * @return true if initialization succeeds
 * @return false if initialization fails
 */
bool UniformSelector::init(ConfigInterface &config, std::string moduleName, std::vector<MutatorModule *> mutators, void *initData)
{
    name = moduleName;

    // Initialize mutator pool
    _MutatorSelector_mutators = mutators;
    
    // Setup uniform distribution map
    num_mutators = mutators.size();
    float uniform_value = 1.0f / num_mutators;
    for (size_t i = 0; i < num_mutators; i++)
        mutator_selection_distribution.push_back(uniform_value);

    // Get RNG for selectMutator
    random = VmfRand::getInstance();

    return true;
}

/**
 * @brief select a mutator
 */
MutatorModule* UniformSelector::selectMutator()
{
    // generate a value within the sum of the distribution * precision factor
    // including the endpoints
    float rand_val = static_cast<float>(random->randBelow(precision_factor + 1));
    size_t i = 0;
    while (i < num_mutators && 0 < rand_val)
        rand_val -= mutator_selection_distribution[i++] * precision_factor_float;
    if (i == 0)
        return _MutatorSelector_mutators[0];
    else
        return _MutatorSelector_mutators[i-1];
}



// Custom Probability Distribution


/**
 * @brief Abstract class defining mutator selection algorithms for stacked mutators
 */
/**
 * @brief Initialize a mutator selection algorithm
 * @param config the ConfigInterface object
 * @param moduleName name of the StackedMutator module
 * @param mutators list of mutators to select from
 * @param initData pointer to arbitrary initialization data
 * @return true if initialization succeeds
 * @return false if initialization fails
 */
bool WeightedRandomSelector::init(ConfigInterface &config, std::string moduleName, std::vector<MutatorModule *> mutators, void *initData)
{
    name = moduleName;

    _MutatorSelector_mutators = mutators;

    num_mutators = mutators.size();

    random = VmfRand::getInstance();

    // Initialize user-provided custom weighted distribution
    mutator_selection_distribution = config.getFloatVectorParam(moduleName, "mutatorSelectionDistribution");

    // assert that distribution covers all mutators and is normalized
    float sum = 0.0;
    size_t num_p = 0;
    for ( auto p : mutator_selection_distribution )
    {
        sum += p;
        num_p++;
    }

    // verify configuration
    if ((1.0 - sum) > FLT_EPSILON)
        throw RuntimeException("The provided mutator selection distribution is not normalized", 
                               RuntimeException::USAGE_ERROR);
    if (num_p != num_mutators){
        LOG_ERROR << "Mismatch in number of probabilities and number of mutators provide: (" << num_p << ", " << num_mutators << ")\n";
        throw RuntimeException("The provided mutator selection distribution is not the same size as the number of mutators", 
                               RuntimeException::USAGE_ERROR);
    }
    
    return true;
}

/**
 * @brief select a mutator
 */
MutatorModule* WeightedRandomSelector::selectMutator()
{
    // generate a value within the sum of the distribution * precision factor
    // including the endpoints
    float rand_val = static_cast<float>(random->randBelow(precision_factor + 1));
    size_t i = 0;
    while (i < num_mutators && 0 < rand_val)
        rand_val -= mutator_selection_distribution[i++] * precision_factor_float;
    if (i == 0)
        return _MutatorSelector_mutators[0];
    else
        return _MutatorSelector_mutators[i-1];
}




// Static Mutator Selector (for fixed stacks)


/**
 * @brief Abstract class defining mutator selection algorithms for stacked mutators
 */
/**
 * @brief Initialize a mutator selection algorithm
 * @param config the ConfigInterface object
 * @param moduleName name of the StackedMutator module
 * @param mutators list of mutators to select from
 * @param initData pointer to arbitrary initialization data
 * @return true if initialization succeeds
 * @return false if initialization fails
 */
bool StaticSelector::init(ConfigInterface &config, std::string moduleName, std::vector<MutatorModule *> mutators, void *initData)
{
    name = moduleName;

    _MutatorSelector_mutators = mutators;
    
    num_mutators = mutators.size();
    
    return true;
}


/**
 * @brief select a mutator
 */
MutatorModule* StaticSelector::selectMutator()
{
    MutatorModule* ret = _MutatorSelector_mutators[curr_mutator];
    curr_mutator = (curr_mutator + 1) % num_mutators;
    return ret;
}


void StaticSelector::startSelect()
{
    curr_mutator = 0;
}


void StaticSelector::endSelect()
{
    curr_mutator = 0;
}