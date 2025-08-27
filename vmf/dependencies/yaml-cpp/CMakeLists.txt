
#Disabled additional yaml targets
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE) 
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
#Add library, but exclude all the targets
message("-- Extracting yaml-cpp")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/yaml-cpp-0.8.0.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/yaml-cpp)
file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-0.8.0)
add_subdirectory(${DEPENDENCIES_DIRECTORY}/yaml-cpp/yaml-cpp-0.8.0 ${DEPENDENCIES_DIRECTORY}/build/yaml-cpp/yaml-cpp-0.8.0 EXCLUDE_FROM_ALL)
