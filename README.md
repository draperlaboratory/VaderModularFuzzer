# VADER Modular Fuzzer (VMF)
- [Downloading & Initializing VMF](#downloading---initializing-vmf)
  * [VMF Compatibility](#vmf-compatibility)
- [Detailed Documentation](#detailed-documentation)
  * [Generate Doxygen Documentation](#generate-doxygen-documentation)
- [Basic Build & Run Instructions](#basic-build---run-instructions)
  * [Building VMF](#building-vmf)
    + [Supplemental Installs](#supplemental-installs)
  * [Run VMF](#run-vmf)
- [License](#license)

### Upgrading from an Earlier Release of VMF?
See [migration-4.0.0.md](docs/migration-4.0.0.md) for a list of the API changes in VMF 4.0.0.

***Note: VMF is compatible with compiler instrumentation from AFL++ 4.10c or earlier, due to an update in the forkserver interface that was introduced in 4.20c.  VMF will be updated in a future release to fix this compatibility issue.***

### VMF Compatibility

As of now, VMF can be run in Docker and on the following distributions of Linux:

- CentOS 8 and 9
- Kali
- Oracle Linux 8 & 9
- RedHat 8 & 9
- Ubuntu 20.04, and 22.04

VMF depends on several open source projects, but uses a "batteries-included" philosophy to dependencies where practical.

The sources of particular versions of these dependencies live inside of the VMF tree.  
For more information about VMF's included package, and other required dependencies, see
[External Projects](docs/external_projects.md)

Either initialize Docker with one of the dockerfiles in [dockerfiles](dockerfiles) or run the equivalent commands within your installation of linux
to install the VMF dependencies (these command can even be copied from the corresponding Dockerfile).

## Detailed Documentation
If you are new to fuzzing, read these documents:
 - [Intro to Fuzzing](docs/intro_to_fuzzing.md): A basic overview of what fuzzing is and how it works.
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

### Building VMF

VMF is build using CMake, see the [Build System Documentation](docs/build_system.md) for details. The build depends on libcurl, which
is often installed by default. You can install this on Debian-based systems (including Ubuntu and Kali) via
```bash
sudo apt install libcurl-dev
```
On CentOS, RHEL, or Fedora, try
```bash
sudo yum install libcurl-devel
```

Execute the following commands to build VMF:

```bash
# from /path/to/vmf/ directory:
mkdir build
cd build
cmake .. && make
```

### Installing VMF

The VMF build binary artifacts, including supporting files for building VMF modules, can be installed
into a tree for distribution.  By default that tree is in the vmf_install directory under the build
directory, but it can be moved anywhere.  If you wish to configure the build from the start to
set an install location, do this:

```bash
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=<your install path here> ..
make
```

To install the VMF build, do this in the build directory (-j8 may be ommitted to build single threaded, but the build will be slower):
```bash
make install -j8
```

The installed tree is position independent, and can be copied anywhere.

### Running VMF
VMF can be run in a standalone mode, with a single fuzzing instance, as well as in a distributed mode where multiple VMF instances work together to fuzz something.

To run VMF in standalone mode:

```bash
cd vmf_install
./bin/vader -c test/config/basicModules.yaml -c test/haystackSUT/haystack_stdin.yaml
```

This will run VMF with a simple System Under Test (SUT) called haystack, providing the fuzzed input to stdin.  Alternatively, you may split the configuration into one or more files and provide as many as desired to VMF.  See [Getting Started #Running VMF Configurations](docs/getting_started.md#running-vmf-configurations) for details.


To run VMF in distributed mode, you must first install the Campaign Data Management Server (CDMS).  See detailed directions in [docs/distributed_fuzzing.md](docs/distributed_fuzzing.md).  Once the server is installed, each individual VMF instance is started using the -d option, to indicated distributed mode.  A small configuration file is provided that contains the information needed to connect to the server.

Note: The linux zip utility is also required for distributed mode.  If the command `which zip` does not return a path to the zip executable, you will need to first install zip on your system:
```bash
sudo apt install zip
```
To run VMF in distributed mode:

```bash
cd vmf_install
./bin/vader -d test/config/serverconfig.yaml
```

### Samples

The samples directory contains samples of how to build a VMF module outside of the full VMF tree.
This directory is installed with the VMF binaries in a distribution install.

## License

VMF is licensed under GNU General Public License Version 2
See [LICENSE](LICENSE)

