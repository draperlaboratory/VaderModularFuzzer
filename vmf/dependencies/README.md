# VMF source controlled dependencies

The VMF depends on a number of external efforts detailed under [the external projects documentation](../../docs/external_projects.md).  They are managed here as archives of source directories that are extracted at configuration time for absorpotion into the VMF build configurations.  Each subdirectory of this directory specifies a single VMF source controlled archive following the naming convention and minimal folder structure:

```bash
<dependency name>/<dependency name>-<git describe format of commit>.zip
<dependency name>/CMakeLists
```

For all dependencies except `klee`.  The `CMakeLists.txt` is responsible for minimally extracting the dependency and specify or absorping its build targets.  The extraction of these dependencies will be under the `DEPENDENCIES_DIRECTORY` by default at `${CMAKE_BINARY_DIR}/build_artifacts/deps`.  The build of these extracted dependencies will be under `${CMAKE_BINARY_DIR}/build_artifacts/deps/build/<dependency name>`.  Dependencies are conditionally added upon host system configuration detection i.e. windows depedencies are only included when building in a windows build shell, see [the build instructions](../../README.md#building-vmf-windows) for further instruction.

## Best Practices for extending source controlled dependencies

* Each dependency should have its own sub-directory that is the name of the software package, not including version/release information
* Source archives should correspond to formal releases or tags. If the vendor does not use release versioning or tagging, the commit ID of "top-of-trunk" should be used as the release identifier.
* Source archives provided by the vendor should be used whenever available. If the vendor does not provide a source archive then a tool-generated archive should be used (e.g. GitHub's "Download ZIP" option). If neither alternative exists then the VMF development team may create a source archive.
* Each dependency source archive file name should include the release version or commit ID, as appropriate
* The dependency's license file(s) should be separately included in the directory
* An integrity check value provided by the vendor should be included whenever available.
