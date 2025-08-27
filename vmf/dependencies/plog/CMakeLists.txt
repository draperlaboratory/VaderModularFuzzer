set(PLOG_INSTALL TRUE CACHE BOOL "" FORCE)
set(PLOG_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
extract_and_build_dep(
  ${CMAKE_CURRENT_SOURCE_DIR}/plog-1.1.10.zip
  plog
  plog/plog-1.1.10
)
