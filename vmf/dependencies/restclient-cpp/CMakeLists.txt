
message("-- Extracting restclient-cpp")
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_SOURCE_DIR}/restclient-cpp-0.5.3.zip
                     DESTINATION ${DEPENDENCIES_DIRECTORY}/restclient-cpp)

file(GLOB matched_dirs ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-*)
list(GET matched_dirs 0 matched_dir)
file(RENAME ${matched_dir} ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3)

file(INSTALL      
     DESTINATION ${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3
     FILES  ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-vmf.txt
     RENAME CMakeLists.txt
     TYPE FILE)

add_subdirectory(${DEPENDENCIES_DIRECTORY}/restclient-cpp/restclient-cpp-0.5.3
                 ${DEPENDENCIES_DIRECTORY}/build/restclient-cpp)
