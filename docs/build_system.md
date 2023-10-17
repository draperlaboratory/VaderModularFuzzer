# VMF Build System Documentation

## Overview

## Debug build

In order to build the project in debug mode, execute the following from the project root directory.

```bash
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make
```

## Generate Doxygen Documentation
 To generate class level Doxygen documentation, run the following commands.  (Doxygen must be installed first.)
 ```bash
 cd docs/doxygen
 doxygen Doxyfile.in
 ```
 Open [docs/doxygen/html/index.html](./doxygen/html/index.html) to browse the resulting html documentation.

 To rebuild the PDF version of the documentation, run the following additional commands:
  ```bash
 cd docs/doxygen/latex
 make
 ```

 Open [docs/doxygen/latex/refman.pdf](./docs/doxygen/latex/refman.pdf) to view the resulting PDF documentation.


## Adding New External Projects

In order to bring in a 3rd party library to VMF you need to:

- Add the appropriate repository as a submodule (in the `submodules` directory), by running this command from the top level vmf directory
```bash
git submodule add --depth=1 http://... ./submodules/NEW_MODULE_NAME
```
- Add an `ExternalProject_add()` command in the `vmf/src/submodules/cmake/superBuild.cmake` file
  - This will need to include an installation command or script to move the headers and binaries needed into
  the `external/` directories `include` and `lib` directories under the moniker
  of the 3rd party library itself. e.g. `external/include/AFLplusplus`.
  - See `vmf/src/submodules/cmake/install-LibAFL-legacy` for an example of an install script
- Add the external project to the build itself (***omit if this is a header only library***)
  - If this is a new dependency for the VMF framework (as opposed to an individual module), then the dependency should be added to  `/vmf/src/framework/CMakeLists.txt`
  - If this is a dependency for a VMF Core Module, then the dependency should be added to `vmf/src/coremodules/CMakeLists.txt`
- Add the library and include paths as CMake variables in the `vmf/cmake/externalProperties.cmake` and `vmf/cmake/external_libs.cmake` files. (***omit if this is a header only library***) 

After adding a new submodule, you will need to rebuild and install the submodules -- see [vmf/submodules/README.md](../vmf/submodules/README.md).  This installs the built submodules into the 'external' directory associated with the particular flavor of linux that you are building on.
