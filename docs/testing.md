# VMF Unit Tests

VMF uses the Google Test framework for unit testing. A basic overview of the framework as well as example unit test are available here: [Primer](http://google.github.io/googletest/primer.html).

## Running the VMF Unit Tests
To run the existing VMF unit tests use the following commands (on windows, be sure to do this in the Developer Command Prompt for Visual Studio)
```bash
cd build
ctest
```

On windows, the unit tests may also be run within Visual Studio by building the RUN_TESTS target.

For additional output on any failed tests
```bash
ctest --output-on-failure
```

For additional output on all of the tests
```bash
ctest --VV
```


## Adding new Unit Tests to `CMake`
To test modules within the VMF repository, additional tests may be added to the existing [/test/unittest/CMakeLists.txt](../test/unittest/CMakeLists.txt).

Alternatively a new CMake file may be created.  Keep in mind that the following three things are needed to run the Google Test framework:

- The test executable must be added to a `CMakeLists.txt` file. e.g.
  ```CMake
    add_executable(exampleTest exampleTest.cpp)
  ```
- The `gtest_main` library must be linked against said executable
  ```CMake
    target_link_libraries(exampleTest
        PUBLIC
            gtest_main
    )
  ```
- The `GoogleTest` CMake module components must be pulled in.
  ```CMake
    include(GoogleTest)
    gtest_add_tests(TARGET exampleTest)
  ```



