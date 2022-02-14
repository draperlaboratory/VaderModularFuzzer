#pragma once

using namespace std;

#include "Module.hpp"

class MutatorModule: public Module {
    public:
        virtual void createInitialTestCases(void) = 0;
        virtual void addNewTestCase(int) = 0;
};
