# VMF Samples

This is a collection of samples showing how to build a VMF module using a VMF installation,
rather than the full VMF source tree.

To build a sample, go to the sample directory and follow this pattern:

```bash
mkdir build
cd build
cmake -DVMF_INSTALL=<root of the VMF install> ..
make
```

To install the resulting sample shared library into the vmf framework use the following command, which will install the library into your VMF_INSTALL plugins directory (-j8 may be ommitted to build single threaded, but the build will be slower).
```bash
make install -j8
```
