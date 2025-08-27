
cmake_minimum_required(VERSION 3.10.2)
if(WIN32)
else()
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(CMAKE_C_COMPILER afl-clang-fast)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")

        add_executable(mime mime.c)
        add_executable(mime_asan mime.c)

        set(BINARY_SOURCE ${CMAKE_SOURCE_DIR}/test/unittest/inputs/AFLForkserverExecutorTest/mimeSUT/mime_legacy)
        set(BINARY_DEST ${CMAKE_BINARY_DIR}/build_artifacts/mime_legacy)
        add_custom_command(
            OUTPUT ${BINARY_DEST}
            COMMAND ${CMAKE_COMMAND} -E copy_if_different ${BINARY_SOURCE} ${BINARY_DEST}
            DEPENDS ${BINARY_SOURCE}
            COMMENT "Copying ${BINARY_SOURCE} to ${BINARY_DEST}"
        )
        add_custom_target(copy_binary ALL DEPENDS ${BINARY_DEST})
        
        set_target_properties(mime PROPERTIES LANGUAGE C)
        set_target_properties(mime_asan PROPERTIES LANGUAGE C)

        target_compile_options(mime_asan PRIVATE -fsanitize=address -g)
        target_link_options(mime_asan PRIVATE -fsanitize=address)
    endif()
endif()
