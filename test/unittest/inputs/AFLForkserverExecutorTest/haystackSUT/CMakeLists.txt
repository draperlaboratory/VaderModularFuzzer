
cmake_minimum_required(VERSION 3.10.2)


find_program(AFL_CLANG_FAST afl-clang-fast)
if (AFL_CLANG_FAST)

    set(CMAKE_C_COMPILER afl-clang-fast)
    set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
    set(CMAKE_C_FLAGS_RELEASE "-O1")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")

    add_executable(haystack_AFL_deferred_ut haystack_AFL_deferred.c)
    add_executable(haystack_AFL_persist_ut haystack_AFL_persist.c)
    add_executable(haystack_AFL_shmem_ut haystack_AFL_shmem.c)
    add_executable(haystack_AFL_hang_ut haystackHang.c)
    
    
    set_target_properties(haystack_AFL_deferred_ut PROPERTIES 
        LANGUAGE C
        OUTPUT_NAME haystack_AFL_deferred_ut)
    set_target_properties(haystack_AFL_persist_ut PROPERTIES
        LANGUAGE C
        OUTPUT_NAME haystack_AFL_persist_ut)
    set_target_properties(haystack_AFL_shmem_ut PROPERTIES
        LANGUAGE C
        OUTPUT_NAME haystack_AFL_shmem_liveness)
    set_target_properties(haystack_AFL_hang_ut PROPERTIES
        LANGUAGE C
        OUTPUT_NAME haystackHang)
endif()
