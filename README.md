# VADER Modular Fuzzer (VMF)
- [VMF Compatibility](#vmf-compatibility)
- [Detailed Documentation](#detailed-documentation)
  * [Generate Doxygen Documentation](#generate-doxygen-documentation)
- [Basic Build & Run Instructions](#basic-build---run-instructions)
  * [Building VMF Linux](#building-vmf-linux)
  * [Building VMF Windows](#building-vmf-windows)
  * [Running VMF](#running-vmf)
- [Building New Modules](#building-new-modules)
- [License](#license)

### Upgrading from an Earlier Release of VMF?
See [migration.md](docs/migration.md) for a list of the API changes in the latest version of VMF.

## VMF Compatibility

As of now, VMF can be run in Docker and on the following distributions of Linux:

- CentOS 8 and 9
- Kali
- Oracle Linux 8 & 9
- RedHat 8 & 9
- Ubuntu 20.04, and 22.04

VMF depends on several open source projects, but uses a "batteries-included" philosophy to dependencies where practical.

VMF can also be run on Windows 10, however the "batteries-included" philosophy is not applied to one major dependancy (FridaRE). This results in a few system configuration and package requirements for building this necessary dependancy. See [Building VMF Windows](#building-vmf-windows)

The sources of particular versions of these dependencies live inside of the VMF tree.  
For more information about VMF's included package, and other required dependencies, see
[External Projects](docs/external_projects.md)

Either initialize Docker with one of the dockerfiles in [dockerfiles](dockerfiles) or run the equivalent commands within your installation of linux
to install the VMF dependencies (these command can even be copied from the corresponding Dockerfile).

## Detailed Documentation
If you are new to fuzzing, read these documents:
 - [Fuzz Harnessing](docs/fuzz_harnessing.md): A basic overview of how to connect a fuzzer to your target code (harnessing)
 - [Glossary](docs/glossary.md): Definitions for common fuzzing & VMF terminology.

If you want to use VMF to fuzz your own System Under Test (SUT), read these documents:
 - [Getting Started with VMF](docs/getting_started.md): More details on running VMF and creating configuration files.
 - [Core Modules](docs/coremodules/core_modules_readme.md): More details on the provided VMF core modules.

If you want to use VMF in distributed mode, with multiple VMF instances working together to fuzz a SUT, read this document:
- [Getting Started with Distributed Fuzzing](docs/distributed_fuzzing.md): How to setup and run in distributed mode.

If you want to extend VMF by adding new modules, read these documents:
 - [Writing New Modules](docs/writing_new_modules.md): How to write your own modules for VMF. 
 - [VMF Software Design](docs/design.md): An in-depth explainer on how VMF works, including the different types of modules it supports.
 - [Unit Test Documentation](docs/testing.md): How to write unit tests for new modules.
 - [Build System Documentation](docs/build_system.md): More details on how to build & run VMF.


## Basic Build & Run Instructions
The VMF build binary artifacts, including supporting files for building VMF modules, can be installed
into a tree for distribution.  By default that tree is in the vmf_install directory under the build
directory, but the build system can be directed to install to a different directory.  The installed tree is position independent, and can be copied anywhere.

### Building VMF (Linux)

VMF is build using CMake, see the [Build System Documentation](docs/build_system.md) for details. The build depends on libcurl, which
is often installed by default. You can install this on Debian-based systems (including Ubuntu and Kali) via
```bash
sudo apt install libcurl-dev
```

Note: You _may_ need to install a libcurl development package built specifically for your host's secure socket layer library via, e.g.,
```bash
sudo apt install libcurl4-openssl-dev
```

On CentOS, RHEL, or Fedora, try
```bash
sudo yum install libcurl-devel
```

Execute the following commands to build and install VMF.

*Note: The -DCMAKE_INSTALL_PREFIX may be used to optionally specify an install location other than the default (build/vmf_install).*

```bash
# from /path/to/vmf/ directory:
mkdir build
cd build
cmake ..
#Or optionally use this version instead to specify an install path
#cmake -DCMAKE_INSTALL_PREFIX=<your install path here> ..
make install -j8
```

If your default C++ compiler is not gcc or clang, you will need to explicitely set the compiler using a cmake flag [see docs/build_system.md for more information](docs/build_system.md).
```bash
$ cmake -DCMAKE_CXX_COMPILER=g++ .. && make
```
### Building VMF (Windows)
To build VMF, Visual Studio must be installed -- the community edition is available at [https://visualstudio.microsoft.com/vs/community/](https://visualstudio.microsoft.com/vs/community/).

The only supported windows execution environment is [Frida](https://frida.re/). The currently supported and tested version is 16.4.8 and their released archive has been added to the VMF repo, for convience, as vmf\dependencies\frida\frida-gum-devkit-16.4.8-windows-x86_64.tar.xz

Run the 64-bit Developer Command Prompt for Visual Studio (e.g. "x64 Native Tools Command Prompt VS 2022"), and navigate to the VMF directory.  Then execute the following commands to generation a solution file for VMF.  The exact version of visual studio must be specified in the final command -- here we specify Visual Studio 2022 Version 17.x.  Use `cmake --help` to see additional generation options.

*Note: The -DCMAKE_INSTALL_PREFIX may be used to optionally specify an install location other than the default (build\vmf_install).*

```powershell
#from \path\to\vmf directory
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
#Or optionally use this version instead to specify an install path
#cmake -G "Visual Studio 17 2022" -DCMAKE_INSTALL_PREFIX=<your install path here> ..
cmake --build . --target INSTALL --config Release
```

You may alternatively open the VMF.sln file that has been generated in the build directory and build the INSTALL  target in the GUI.

More information on the build system is available in our [Build System Documentation](docs/build_system.md).

### Running VMF
VMF can be run in a standalone mode, with a single fuzzing instance, as well as in a distributed mode where multiple VMF instances work together to fuzz something.

#### Linux Directions

To run VMF in standalone mode:

```bash
cd vmf_install
./bin/vader -c test/config/basicModules.yaml -c test/haystackSUT/haystack_stdin.yaml
```

This will run VMF with a simple System Under Test (SUT) called haystack, providing the fuzzed input to stdin.  Alternatively, you may split the configuration into one or more files and provide as many as desired to VMF.  See [Getting Started #Running VMF Configurations](docs/getting_started.md#running-vmf-configurations) for details.

#### Windows Directions
To run VMF in standalone mode:

```powershell
cd vmf_install
.\bin\vader.exe -c test/config/basicModules_windows.yaml -c test/haystackSUT/haystack_libfuzzer.yaml
```

This will run VMF with a simple System Under Test (SUT) called haystack, using the FridaRE instrumentation library and the VMF windows Frida runtime (RT) for providing input and collecting coverage.  Alternatively, you may split the configuration into one or more files and provide as many as desired to VMF.  See [Getting Started #Running VMF Configurations](docs/getting_started.md#running-vmf-configurations) for details.

#### Distributed Directions
To run VMF in distributed mode, you must first install the Campaign Data Management Server (CDMS).  See detailed directions in [docs/distributed_fuzzing.md](docs/distributed_fuzzing.md).  Once the server is installed, each individual VMF instance is started using the -d option, to indicated distributed mode.  A small configuration file is provided that contains the information needed to connect to the server.

Note: On linux, the linux zip utility is also required for distributed mode (on windows the required tar utility is included with the Windows OS).  If the command `which zip` does not return a path to the zip executable, you will need to first install zip on your system:
```bash
sudo apt install zip
```

Linux command to run VMF in distributed mode:
```bash
cd vmf_install
./bin/vader -d test/config/serverconfig.yaml
```

Windows command to run VMF in distributed mode:
```powershell
cd vmf_install
.\bin\vader.exe -d test\config\serverconfig.yaml
```

## Building New Modules

The samples directory contains samples of how to build a VMF module outside of the full VMF tree.
This directory is installed with the VMF binaries in a distribution install.

## License

VMF is licensed under GNU General Public License Version 2
See [LICENSE](LICENSE)

