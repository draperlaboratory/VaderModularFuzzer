
cmake_minimum_required(VERSION 3.10.2)

if(NOT WIN32)
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build_artifacts)
        set(LANGUAGE c)

        set(CMAKE_C_COMPILER afl-clang-fast)
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s")
        
	add_library(VMFDriver STATIC VMFDriver.c)

	install(TARGETS VMFDriver
	    LIBRARY DESTINATION ${VMF_INSTALL_LIBDIR})
    endif()
endif()
