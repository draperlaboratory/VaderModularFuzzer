# Suppress warnings in 3rd party code
add_compile_options(-w)

# Test libs
set(INSTALL_GTEST off CACHE BOOL "Don't install test libs" FORCE)
add_subdirectory(googletest)

# Product depdendency libs. These are built statically and linked to VMFFramework
set(BUILD_SHARED_LIBS off)
add_compile_options(-fPIC)
add_subdirectory(json11)
add_subdirectory(plog)
add_subdirectory(restclient-cpp)
add_subdirectory(uthash)
add_subdirectory(yaml-cpp)

add_subdirectory(klee)