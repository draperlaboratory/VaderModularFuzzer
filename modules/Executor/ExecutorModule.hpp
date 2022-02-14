#pragma once

using namespace std;

class ExecutorModule : public Module {
    public:
        void registerStorageNeeds(void);
        void runTestCase(int test_case_id);
        void run(void) = 0;
        void init(void) = 0;
        void shutdown(void) = 0;
};