# Prebuilt External Libraries

This directory contains prebuilt external libraries used in the build.
The submodules directory contains the sources used to produce these builds.

We use prebuilt libraries because the aggregate collection of
libraries can be somewhat challenging to build, or very space
consuming.  Some libraries that we consider using may require
pre-requisite installs that must be installed using sudo, which can
disqualify their use on some systems.

We accept a tradeoff by choosing between building the external
libraries as part of the regular VMF build and using prebuilt
versions.  The prebuilt versions are somewhat brittle, being bound to
the versions of the operating systems on which they were built.  The
prebuilt versions for Ubuntu 18 will not work on Ubuntu 20, for
example, because they bind to different versions of Python libraries,
which are discovered at build time.  The tradeoff is worth it in terms
of simplifying the build process for VMF for the majority of clients
and developers.

If you need a different version of the external libraries built, be
sure to read and understand
[cmake/external_libs.cmake](../cmake/external_libs.cmake), as well as
the submodules [README](../submodules/README.md).

Currently, we support prebuilt versions of the external libraries for
the following operating system versions:
	* Ubuntu 18 (buster)
	* Ubuntu 20 (bullseye)
	* Ubuntu 22 (bookworm)

The subdirectories here are named using the official release names of
the Ubuntu systems they support.  Those names are discoverable on
Ubuntu.  If you changes the directory names, you will break the build.
