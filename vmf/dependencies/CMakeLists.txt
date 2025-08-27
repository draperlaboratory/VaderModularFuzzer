
# Product depdendency libs. These are built statically and linked to VMFFramework
# Suppress warnings in 3rd party code
set(BUILD_SHARED_LIBS off)
add_compile_options(-w)
add_compile_options(-fPIC)
set(DEPENDENCIES_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts/deps)

function(extract_and_build_dep PKG PKG_NAME INCLUDE_PATH)
  message("-- Extracting ${PKG_NAME}")
  file(ARCHIVE_EXTRACT INPUT ${PKG} DESTINATION  ${DEPENDENCIES_DIRECTORY}/${PKG_NAME})
  file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/${PKG_NAME}/${PKG_NAME}-*)
  list(GET matched_dirs 0 matched_dir)
  file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/${INCLUDE_PATH})
  add_subdirectory(${DEPENDENCIES_DIRECTORY}/${INCLUDE_PATH} ${DEPENDENCIES_DIRECTORY}/build/${PKG_NAME})
endfunction()

if(WIN32)
    message("-- Including windows dependencies")
    add_subdirectory(wingetopt)
    add_subdirectory(curl_windows)

    #windows-only dependencies
    if(NOT DEFINED FRIDA_PKG)
        set(
            FRIDA_PKG "${CMAKE_CURRENT_SOURCE_DIR}/frida/frida-gum-devkit-16.4.8-windows-x86_64.tar.xz" 
            CACHE STRING "Path to selected frida binary"
        )
    endif()
else()
    message("-- Including linux dependencies")
    add_subdirectory(klee)
endif()

add_subdirectory(googletest)
add_subdirectory(plog)
add_subdirectory(yaml-cpp)
add_subdirectory(uthash)
add_subdirectory(json11)
add_subdirectory(restclient-cpp)