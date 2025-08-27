# Note: CMake support is community-based. The maintainers do not use CMake
# internally.


# Test libs
set(INSTALL_GTEST on CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

set(GTEST_LIBRARY ${CMAKE_BINARY_DIR}/lib/libgtest.a)
set(GTEST_MAIN_LIBRARY ${CMAKE_BINARY_DIR}/lib/libgtest_main.a)
set(GTEST_INCLUDE_DIR ${DEPENDENCIES_DIRECTORY}/googletest/googletest-1.17.0/googletest/include)
extract_and_build_dep(
  ${CMAKE_CURRENT_SOURCE_DIR}/googletest-1.17.0.zip
  googletest
  googletest/googletest-1.17.0/
)


