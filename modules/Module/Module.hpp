#pragma once

using namespace std;

class Module {
    public: 
        virtual void init() = 0;
        virtual void registerStorageNeeds() = 0;
        virtual void run() = 0;
    protected:
        SUT* current_sut;
        Module(string path, string[] params);
}:

typedef struct {
    string path;
    string[] params;
} SUT;