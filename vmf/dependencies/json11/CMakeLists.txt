message("-- Extracting json11")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/json11-1.0.0.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/json11)

file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/json11/json11-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0)

add_library(json11 STATIC ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0/json11.cpp)
target_include_directories(json11 PUBLIC ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0)
install(FILES ${DEPENDENCIES_DIRECTORY}/json11/json11-1.0.0/json11.hpp DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vmf COMPONENT CPP_INCLUDES)

