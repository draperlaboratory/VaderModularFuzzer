find_program(KLEE_EXEC klee)

if (KLEE_EXEC)
    message(STATUS "KLEE found: ${KLEE_EXEC}")

    set(SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/test/haystackSUT/haystack.c
    )
    
    add_custom_target(haystack.bc ALL
        COMMAND clang -emit-llvm -c -o haystack.bc ${SOURCE_FILES}
        DEPENDS ${SOURCE_FILES}
    )
else ()
    message(STATUS "KLEE not found.  Skipping KLEE bitcode generation.")
endif()