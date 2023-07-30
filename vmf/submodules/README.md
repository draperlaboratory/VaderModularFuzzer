# External Libraries Collection

The submodules directory contains various external dependencies needed
by the VMF build.  These are prebuilt and delivered into the
'external' subdirectory.  See the [/external/README](../external/README.md)
there for more information.

If you need to rebuild these libraries, make sure all your submodules
have been initialized:
```
git submodule update --init --depth=1
```

Then in the submodules directory:
```
mkdir build
cd build
cmake ..
make
```

Then install the built libraries into the 'external' directory with:
```
make install
```

Note that the installation will discover which version of Ubuntu you
are running on and install the build artifacts into a version specific
directory.  Once the build artifacts are installed, they can be
checked into git.

One thing to be aware of is that the build of third party libraries
can be sensitive to which packages are installed on your system.  For
example, the Google Logging build (glog) will note if you have
the 'gflags' package installed, and if so will generate a different
header file than if you did not have it installed.  This can cause
breakage if you build on a system that has 'gflags' installed, check
in the build artifacts, and then try to use them on a system that does
not have 'gflags' installed.  If possible, build on a Ubuntu system
that is known to have only the prerequisite packages that VMF
advertises as requirements.  One way to ensure this is to maintain a
VM for Ubuntu 18 and Ubuntu 20 that is used purely as a build
environment, so you do not accidentally install packages for other
projects or purposes and affect the third party library builds.
