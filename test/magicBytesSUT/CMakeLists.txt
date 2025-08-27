
cmake_minimum_required(VERSION 3.10.2)
if(WIN32)
else()
    find_program(AFL_CLANG_FAST afl-clang-fast)
    if (AFL_CLANG_FAST)
        set(CMAKE_C_COMPILER afl-clang-fast)
        set(CMAKE_C_FLAGS "-O1 ${CMAKE_C_FLAGS}")
        set(CMAKE_C_FLAGS_RELEASE "-O1")

        add_executable(magicbytes magicbytes.c)
        add_executable(magicbytes_cmplog magicbytes.c)
        
        set_target_properties(magicbytes_cmplog PROPERTIES LANGUAGE C)
        set_target_properties(magicbytes_cmplog PROPERTIES 
            RULE_LAUNCH_COMPILE "AFL_LLVM_CMPLOG=1")
        install(TARGETS magicbytes magicbytes_cmplog
            RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/test/magicBytesSUT)
    endif()
endif()
