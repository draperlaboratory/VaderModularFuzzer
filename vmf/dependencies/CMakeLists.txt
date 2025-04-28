# Suppress warnings in 3rd party code
add_compile_options(-w)

# Test libs
set(INSTALL_GTEST off CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
add_subdirectory(googletest)

if(WIN32)
#windows-only dependencies
if(NOT DEFINED FRIDA_PKG)
  set(FRIDA_PKG "${CMAKE_CURRENT_SOURCE_DIR}/frida/frida-gum-devkit-16.4.8-windows-x86_64.tar.xz" CACHE STRING "Path to selected frida binary")
endif()
add_subdirectory(curl_windows)
add_subdirectory(wingetopt)
else()
#linux-only dependencies
add_subdirectory(klee)
endif()


# Product depdendency libs. These are built statically and linked to VMFFramework
set(BUILD_SHARED_LIBS off)
add_compile_options(-fPIC)
add_subdirectory(json11)
add_subdirectory(plog)
add_subdirectory(restclient-cpp)
add_subdirectory(uthash)

#Disabled additional yaml targets
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE) 
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
#Add library, but exclude all the targets
add_subdirectory(yaml-cpp EXCLUDE_FROM_ALL)
add_dependencies(yaml-cpp yaml-cpp)

