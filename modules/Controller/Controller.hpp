#pragma once
using namespace std;

class ControllerModule : public Module {
    public:
        TODO registerStorageNeeds(void);
        virtual void run(void) = 0;
        virtual void init(void) = 0;
        virtual void shutdown(void) = 0;
};