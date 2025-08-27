
message("-- Extracting uthash")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/uthash-2.3.0.zip DESTINATION ${DEPENDENCIES_DIRECTORY}/uthash)
add_library(uthash INTERFACE)
target_include_directories(uthash INTERFACE ${DEPENDENCIES_DIRECTORY}/uthash/uthash-2.3.0/src)
