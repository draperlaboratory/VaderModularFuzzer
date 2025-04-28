# VMF Module Templates

This is a set of templates for VMF modules that can be used as a starting point for writing new modules.  These templates can also be built and installed into VMF, using the provided make system, though they do not really fuzz anything.

Note: Templates are not provided for ControllerModule and StorageModule.  If you are writing a Controller module, start by taking a look at the IterativeController as an example.

## Building the Template Modules
To build the module templates, go to the moduleTemplate directory and follow this pattern:

```bash
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=<root of the VMF install> ..
make
```

To install the resulting module template library into the vmf framework use the following command, which will install the library into your VMF_INSTALL plugins directory (-j8 may be ommitted to build single threaded, but the build will be slower).
```bash
make install -j8
```
## Executing the Template Modules
These templates can also be executed using the example configuration file [config/modulesTemplates.yaml](config/moduleTemplates.yaml).  Note that these are just templates for development, not real fuzzing modules, so the resulting VMF "fuzzer" doesn't really fuzz anything.

To execute, run the following from the VMF_INSTALL directory
```
./bin/vader -c <path to moduleTemplates.yaml>
```
