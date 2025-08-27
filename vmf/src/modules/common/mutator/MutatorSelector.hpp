#include "MutatorModule.hpp"
#include "VmfRand.hpp"

#pragma once

using namespace vmf;

/**
 * @brief Abstract class defining mutator selection algorithms for stacked mutators
 */
class MutatorSelector
{
public:
    /**
     * @brief Initialize a mutator selection algorithm
     * @param config the ConfigInterface object
     * @param moduleName name of the StackedMutator module
     * @param mutators list of mutators to select from
     * @param initData pointer to arbitrary initialization data
     * @return true if initialization succeeds
     * @return false if initialization fails
     */
    virtual bool init(ConfigInterface &config, std::string moduleName, std::vector<MutatorModule *> mutators, void *initData) = 0;

    /**
     * @brief perform actions before selecting mutator(s) in a stack
     */
    virtual void startSelect() = 0;

    /**
     * @brief select a mutator
     */
    virtual MutatorModule *selectMutator() = 0;

    /**
     * @brief perform actions after selecting mutator(s) in a stack
     */
    virtual void endSelect() = 0;

    virtual ~MutatorSelector() {}

    /**
     * @brief Get the name of the module
     * This is a unique brief descriptive name of the module that is used to map configuration
     * information to module instances.
     * 
     * @return std::string 
     */
    std::string getModuleName() { return name; }
protected:
    /// The module name of the MutatorSelector Class Object
    std::string name;
    /// The pool of mutators to select over (owned by StackedMutator class)
    std::vector<MutatorModule*> _MutatorSelector_mutators;
    /// The number of mutators in the pool
    size_t num_mutators;

    // configs constants
    // precision factors for random mutator selection

    /// The precision factor random number generation, see non-static mutator class 
    /// implementations of selectMutator for an example
    int precision_factor = 100;
    /// The float for how finely to specify the range random selection
    float precision_factor_float = static_cast<float>(precision_factor);

    /// The probability distribution to select over the mutators with
    std::vector<float> mutator_selection_distribution;

    /// A pointer to the VMF Random modules
    VmfRand* random;
};

// Instances of this abstract selector class

/**
 * @brief Static Mutator Selector for static mutation stacks
 */
class StaticSelector : public MutatorSelector {
public:
    void endSelect();
    MutatorModule *selectMutator();
    bool init(ConfigInterface&, std::string, std::vector<MutatorModule*>, void*);
    void startSelect();
private:
    int curr_mutator = 0;
};


/**
 * @brief Uniform Mutator Selector for dynamically generated mutation stacks with uniformly random selection probability distribution
 */
class UniformSelector : public MutatorSelector {
public:
    void endSelect(){};
    MutatorModule *selectMutator();
    bool init(ConfigInterface&, std::string, std::vector<MutatorModule*>, void*);
    void startSelect(){};
};

/**
 * @brief Custom Mutator Selector for dynamically generated mutation stacks with non-uniformly random selection probability distribution
 */
class WeightedRandomSelector : public MutatorSelector {
public:
    void endSelect(){};
    MutatorModule *selectMutator();
    bool init(ConfigInterface&, std::string, std::vector<MutatorModule*>, void*);
    void startSelect(){};
};