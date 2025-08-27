
cmake_minimum_required(VERSION 3.10.2)

if(WIN32)
    # add_library(haystack_libfuzzer_lib SHARED haystack_libfuzzer.c)
    add_executable(haystack_libfuzzer haystack_libfuzzer.c)

    # set_target_properties(haystack_libfuzzer_lib PROPERTIES LANGUAGE C++)
    set_target_properties(haystack_libfuzzer PROPERTIES LANGUAGE C++)
    
    link_directories(${VMF_INSTALL_LIBDIR})
    target_link_libraries(haystack_libfuzzer vmf_frida_rtlib vmf_frida_rtembed shell32)
    target_link_options(haystack_libfuzzer PRIVATE /subsystem:console)

    install(TARGETS haystack_libfuzzer
        RUNTIME DESTINATION test/haystackSUT)
    # install(TARGETS haystack_libfuzzer_lib
    #     LIBRARY DESTINATION test/haystackSUT
    #     RENAME haystack_libfuzzer.dll)
else()
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts)
        set(LANGUAGE c)

        set(CMAKE_C_COMPILER afl-clang-fast)
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")
        
        add_executable(haystack haystack.c)
        add_executable(haystack_AFL_shmem haystack_AFL_shmem.c)
        add_executable(haystack_AFL_deferred haystack_AFL_deferred.c)
        add_executable(haystack_AFL_persist haystack_AFL_persist.c)

        install(TARGETS haystack haystack_AFL_shmem haystack_AFL_deferred haystack_AFL_persist
            RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/test/haystackSUT)
    endif()
endif()
